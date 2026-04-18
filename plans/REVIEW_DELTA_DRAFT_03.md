# Round-3 review — delta since draft-02r1

**Target version**: `xenia-wire 0.2.0-alpha.3` / SPEC **draft-03**.
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
`v0.2.0-alpha.3`. Source-file references are to the reference
implementation at the same tag.

**What changed, precisely.** §1–§11 (envelope layout, nonce
construction, replay window, AEAD, payload type registry) are
byte-for-byte identical to draft-02r1. The deltas are confined
to §12 (Consent Ceremony) in three layers:

1. **Canonical signed-body contract** — breaking change in
   `0.2.0-alpha.1`: `ConsentRequestCore` / `ConsentResponseCore`
   / `ConsentRevocationCore` each gained a mandatory 32-byte
   `session_fingerprint` field at a fixed canonical position.
2. **Receive-side state machine** — breaking change in
   `0.2.0-alpha.1`: normative transition table (§12.6.1),
   `ConsentEvent` carries `request_id`, `observe_consent`
   returns `Result`.
3. **Receive-side hardening, no-wire-change** — in
   `0.2.0-alpha.2` and `0.2.0-alpha.3`: rekey-aware
   fingerprint verify, timing-channel assumption, constant-
   time dual-derivation path during grace window.

Sender-side behavior is unchanged from an integrator's
perspective once the struct-literal migration (point 1) is
done. Receiver-side behavior gained both the new error channel
(point 2) and the hardened verify path (point 3).

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

  > **Design-evolution note (surfacing an earlier divergence).**
  > An earlier internal plan bound the fingerprint to the
  > *initial* session key so it would be stable across rekeys.
  > The shipped design binds to the *current* key and handles
  > rekey via the verifier's both-key probe. Rationale is
  > captured in §12.3.1 (no wire-level representation of
  > "initial"; preserving an initial key fights zeroization;
  > the grace window bounds the probe cost the same way it
  > bounds AEAD-verify). Flagged here so it reads as evolution
  > rather than inconsistency.
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
explicitly LE per §3).

**Framing (rewritten for clarity).** The choice is intentionally
domain-separated deterministic encoding — not a claim that
big-endian is semantically meaningful for `request_id`. HKDF's
`info` parameter needs fixed, unambiguous bytes; any normative
byte order works. Picking BE here means a careless implementer
who reuses the ambient LE encoding path produces an obviously
wrong fingerprint and fails at the verify step, instead of
silently producing a wrong-but-plausible output. The defensive
effect is the whole reason; it's not a cryptographic property.

**Specific ask.** Is this defensive asymmetry worth it, or
does the interop cost of the mixed convention outweigh the
mistake-reduction gain?

We acknowledge this is the weakest design choice in the
cryptographic set — **defensible, not elegant.** If the
reviewer recommends normalizing to all-little-endian, we're
willing to do it in the next breaking draft (draft-04 /
`0.3.0`). Not a draft-03 blocker; documenting the stance
upfront so the reviewer knows it's on the "change next time"
shortlist rather than an entrenched position.

### 2.3 Timing side-channel in `verify_fingerprint_either_epoch` (RESOLVED in 0.2.0-alpha.3)

**Original question.** The 0.2.0-alpha.2 implementation of
`verify_fingerprint_either_epoch` derived the fingerprint against
the current key, compared, and — on mismatch — derived against
the previous key. That's one HKDF call on match, two on
mismatch, which leaks which key-epoch signed the consent via
verify-path latency.

**Resolution (0.2.0-alpha.3).** The reference implementation now
derives fingerprints against BOTH keys unconditionally whenever
`prev_session_key` is present, and combines the constant-time
compares with a non-short-circuiting bitwise OR (`bool` `|`, not
`||`). The extra HKDF-SHA-256 call is only incurred during the
grace window. SPEC §12.3.1 rekey interaction now states this as
a normative MUST for receivers.

**Ask becomes:** review confirmation that the fix is sufficient.
The reasoning we want confirmed, stated crisply:

> The presence of a previous session key is **protocol-visible
> operational state, not secret key material.** The rekey grace
> window is a protocol-level feature (§6.2, default 5s) whose
> start and end are observable to any on-path attacker from
> nonce counter resets, AEAD-verify failures, and the mere
> appearance of messages that only decrypt under the previous
> key. An attacker who can measure verify-path timing gains
> nothing from learning "prev key is present" that they cannot
> already infer from these other signals. The dual-HKDF cost is
> therefore needed only to hide **which** epoch matched — not
> whether the grace window is active. alpha.3 hides the former;
> hiding the latter would require constant-time dummy
> derivations and an indistinguishable grace-window state
> machine, which we judge out of scope for a wire protocol.

Please confirm the underlined claim ("protocol-visible
operational state, not secret") is sufficient justification for
not adding constant-time dummy derivations outside the grace
window.

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

### 2.6 §12.8 timing-channel scope — any missing sinks?

**The question.** §12.8 enumerates three operations on the verify
path that MUST NOT branch on secret-dependent bytes: bincode
deserialization of the signed body, Ed25519 signature verify, and
the 32-byte constant-time fingerprint compare. Did we miss a
fourth timing-observable? Two candidates we considered and
rejected as not-a-sink: the Ed25519 `from_slice` signature-length
check (the signature length is 64 bytes and public), and
bincode's length-prefix parse for the `reason: String` field
(the length byte is part of the attacker-controlled input
rather than a secret).

**Specific ask.** Confirm the three-sink list is exhaustive, or
point at a sink we missed.

---

## 3. Pointers

- **SPEC**: `SPEC.md` at tag `v0.2.0-alpha.3` on
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
