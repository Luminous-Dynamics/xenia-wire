# Round-3 review — delta since draft-02r1

**Target version**: `xenia-wire 0.2.0-alpha.2` / SPEC **draft-03**.
**Assumed prior context**: you last reviewed **draft-02r1**
(`xenia-wire 0.1.0-alpha.3` / `alpha.4`, April 2026), which flagged
four open design items: session-binding (loose), split-Pending,
duplicate/conflict consent semantics, configurable replay window.

This document is the scoped follow-up. It is deliberately short:

- **§1** is the deltas since draft-02r1 — nothing you haven't seen
  before if you tracked Appendix B, but collected here for quick
  orientation.
- **§2** is six targeted questions ranked by cryptographic weight.
  Questions 1-3 are where we genuinely would like an independent
  opinion; 4-6 are lower-risk "any concerns?" items.

Section-number references (e.g., §12.3.1) are to SPEC.md at
`v0.2.0-alpha.2`. Source-file references are to the reference
implementation at the same tag.

---

## 1. Deltas since draft-02r1

### draft-02r2 (shipped `0.1.0-alpha.5`, no wire change)

- Split `ConsentState::Pending` into **`LegacyBypass`** (default,
  sticky) and **`AwaitingRequest`** (opt-in via
  `SessionBuilder::require_consent(true)`). Pure receiver-local;
  no envelope bytes change.
- Replay window parameterized: `W ∈ {64, 128, 256, 512, 1024}`
  bits, default 64. Multi-word bitmap shift internal to
  `ReplayWindow`. Peers agree on `W` out-of-band.

These are bookkeeping; we don't expect review input unless you see
a hazard.

### draft-03 (shipped `0.2.0-alpha.1`, **breaking** at signed-body layer)

- **Mandatory `session_fingerprint: [u8; 32]`** on all three signed
  cores (`ConsentRequestCore`, `ConsentResponseCore`,
  `ConsentRevocationCore`). Canonical field order pinned in §12.3
  and is normative. Derivation specified in §12.3.1:

  ```
  salt = b"xenia-session-fingerprint-v1"       (28 bytes ASCII)
  ikm  = current AEAD session_key               (32 bytes)
  info = source_id || epoch || request_id_be    (8 + 1 + 8 = 17 bytes)
  L    = 32
  HKDF-SHA-256(salt, ikm).expand(info, L) -> fingerprint
  ```

- **Normative transition table for the consent state machine**
  (§12.6.1). Covers every (state, event, `request_id`-predicate)
  tuple. Three defined protocol violations surface as
  `WireError::ConsentProtocolViolation(ConsentViolation)`:

  - `RevocationBeforeApproval { request_id }`
  - `ContradictoryResponse { request_id, prior_approved, new_approved }`
  - `StaleResponseForUnknownRequest { request_id }`

  `ConsentEvent` variants now carry `{ request_id }`.
  `Session::observe_consent` returns `Result<ConsentState,
  ConsentViolation>`. On violation, state is NOT mutated; the wire
  does not tear down the transport.

- **UI-guidance subsection §12.6.2** — "change of mind after
  approval" MUST be expressed as a fresh `ConsentRevocation`, never
  as a contradictory `ConsentResponse`. This was the contentious
  decision during internal review: we considered "later-wins" on
  contradictory `ConsentResponse`, rejected it because (a) the
  `ConsentResponseCore` body carries no timestamp, and (b) a
  captured late-Denied from a prior session could force teardown
  on a new Approved one if the fingerprint ever reused across
  ceremonies. Rejection aligns with the decision to make
  fingerprint mandatory.

- **Security-properties rewrite §12.8**: the "LOOSE binding"
  bullet from draft-02r1 becomes "TIGHT binding". New
  protocol-violation-detection bullet for the transition table.

### draft-03 hardening (shipped `0.2.0-alpha.2`, no wire or API change)

- **Rekey-aware fingerprint verify.**
  `Session::verify_consent_{request,response,revocation}` now
  probe **both** the current and (if present) the previous session
  keys when comparing the embedded fingerprint. A consent message
  AEAD-verified under the previous key during the grace window
  now also passes the fingerprint check. §12.3.1 rekey
  interaction spells this out.
- **Timing-channel assumption (§12.8)** — new paragraph. Asserts
  the verify pipeline (bincode deserialize, Ed25519 verify,
  fingerprint compare) MUST NOT branch on secret-dependent bytes.
  Reference impl ships an inline constant-time 32-byte compare
  (`src/session.rs::ct_eq_32`); alternate-language implementers
  are on the hook for auditing bincode-equivalents and Ed25519
  libs.
- **Test vectors 10/11/12** for the three `ConsentViolation`
  variants (event-sequence format; grammar in
  `test-vectors/10_revocation_before_approval.txt`).
- **`cargo-fuzz` target `fuzz_observe_consent`** asserting four
  invariants per step: no panic, state always valid, seal-gate
  matches state, violations never mutate state.

Not in this review cycle: the paper draft (no crypto changes), the
reference LZ4 path (unchanged since draft-02), the replay window
parameterization (mechanical generalization of the draft-02 fixed
64).

---

## 2. Questions ranked by weight

### 2.1 `session_fingerprint` `info` composition (§12.3.1)

**The question.** Is `info = source_id || epoch || request_id_be`
the right input set?

**Alternatives considered:**

| Variant | Property |
|---|---|
| `info = []` | Session-key-only binding. Per-ceremony replay opens up inside a single session. |
| `source_id ‖ epoch` | Session-identity binding. A `ConsentResponse` signed for `request_id=7` is replayable as one for `request_id=8` — undesirable. |
| **`source_id ‖ epoch ‖ request_id_be` (chosen)** | Per-ceremony binding. What's shipped. |
| `source_id ‖ epoch ‖ request_id_be ‖ pld_type` | Per-message-type per-ceremony binding. Would give a distinct fingerprint per message kind. Avoids a hypothetical attack where a captured Response is replayed as a Revocation; we don't currently see that attack, but it's not impossible. |

**Specific ask.** Is the chosen set sufficient for a signed-consent
replay threat model, or should `pld_type` be mixed into `info`?

### 2.2 Big-endian `request_id` in `info`

**The question.** SPEC §12.3.1 specifies `request_id_be` — the u64
in big-endian. Every other integer on the Xenia wire is
little-endian (per bincode v1 default; nonce sequence bytes are
explicitly LE per §3). The mixed convention is intentional — we
wanted the `info` byte-order to differ from the ambient wire so
that an implementation reaching for a "byte-encode this u64 the
usual way" path would produce the wrong fingerprint and fail
loudly rather than silently.

**Specific ask.** Is this mistake-reduction smart, or is it a
footgun that buys nothing because the endianness is already
specified normatively either way?

### 2.3 Timing side-channel in `verify_fingerprint_either_epoch`

**The question.** On the receive path, `verify_consent_*` derives
the fingerprint against the **current** key, compares, and — only
if that fails — derives again against the **previous** key.
That's one HKDF call on match, two on mismatch. Relevant source:
`src/session.rs::verify_fingerprint_either_epoch` (around line
340-360 in the 0.2.0-alpha.2 tree).

An attacker observing verify-path timing could distinguish
"accepted under current key" from "accepted under prev key" from
"rejected". The latency delta is ~one HKDF-SHA-256 derivation
(~a few microseconds on commodity hardware). Is this exploitable?

**Mitigation considered.** Always derive both fingerprints
regardless of first-match outcome; compare each; OR the
constant-time compare results. Constant-time verify path at the
cost of one extra HKDF call per verify. Open to your opinion on
whether this is worth the complexity.

### 2.4 Transition-table completeness (§12.6.1)

**The question.** The table enumerates (state × event ×
`request_id`-predicate). One corner case I want to probe:
`LegacyBypass` + any event → sticky no-op, including a perfectly
valid `ConsentRequest` whose fingerprint matches a local
derivation.

Is sticky the right rule, or should there be a documented
"upgrade from LegacyBypass to ceremony mode" path for deployments
that start permissive and later want to enforce? Currently the
only upgrade path is constructing a new `Session` via
`SessionBuilder::require_consent(true)`.

### 2.5 `ConsentResponse` / `ConsentRevocation` timestamp asymmetry

**The question.** `ConsentRevocationCore` has `issued_at: u64`
(Unix epoch seconds). `ConsentResponseCore` does NOT. This was
intentional in draft-02 and carried forward; we want to confirm
it's still OK given the draft-03 `session_fingerprint`.

Argument for leaving the asymmetry: within a single ceremony, the
state machine forbids a replayed Response (idempotent same-value
Response is a no-op; differing-value is `ContradictoryResponse`
hard-error). Across ceremonies, the fingerprint's `request_id_be`
distinguishes them. So no replay window exists.

Argument for adding `issued_at` to ConsentResponse anyway: the
audit-trail use case (§12.8 third-party-verifiable signed consent)
benefits from knowing *when* the user signed the approval, not
just *that* they did. Currently a replayed (same-value)
`ConsentResponse` would be indistinguishable from the original in
a frozen transcript.

### 2.6 General coherence of §12.8 security properties + §12.10 out-of-scope

**The question.** §12.8 now enumerates: third-party-verifiable
signed consent, TIGHT session binding, protocol-violation
detection, no human-identity binding, and the timing-channel
assumption. §12.10 lists the explicit out-of-scope items (coerced
consent, human-identity fraud, clock-skew attacks).

Is there a property draft-03 implicitly offers that §12.8 should
claim explicitly? Or a threat draft-03 implicitly tolerates that
§12.10 should flag? Open-ended reality-check question.

---

## 3. Pointers

- **SPEC**: `SPEC.md` at tag `v0.2.0-alpha.2` on
  `Luminous-Dynamics/xenia-wire`. §12.3, §12.3.1, §12.6.1, §12.6.2,
  §12.8 are the draft-03 deltas. Appendix B row for draft-03
  records the changelog.
- **Reference implementation**: `src/consent.rs` (all three Core
  types + ConsentViolation + ConsentEvent), `src/session.rs`
  (`session_fingerprint`, `session_fingerprint_from_key`,
  `verify_fingerprint_either_epoch`, `observe_consent` with the
  draft-03 transition table, `ct_eq_32`), `src/error.rs`
  (`WireError::ConsentProtocolViolation`).
- **Test vectors**: `test-vectors/07_consent_request.*`,
  `08_consent_response.*`, `09_consent_revocation.*` for the
  happy-path signed bodies; `10_revocation_before_approval.txt`,
  `11_contradictory_response.txt`, `12_stale_response.txt` for the
  violation event-sequence DSL (grammar documented in file 10).
- **Fuzz target**: `fuzz/fuzz_targets/fuzz_observe_consent.rs`
  with the four invariants.
- **Migration**: `MIGRATION.md` (0.1.x → 0.2.0-alpha.1, plus
  alpha.1 → alpha.2). Paired with `CHANGELOG.md` per-release
  entries.

## 4. Feedback logistics

Any form works. If you prefer structured feedback: a per-section
reply keyed to the six questions above is the highest-bandwidth
format. If you'd rather leave comments inline in a PR against the
`SPEC.md` tree, that's also fine — we'll open a draft `spec-review`
PR on request.

Thank you for taking the time. Rounds 1 and 2 caught real issues;
this round is targeted at confirming the close-out rather than a
full re-read.
