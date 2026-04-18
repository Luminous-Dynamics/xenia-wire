# Migration guide

Worked examples for every API break between published
`xenia-wire` versions. Paired with the per-release entries in
`CHANGELOG.md` — this file focuses on the concrete *before*
and *after* of integrator code, not the rationale for each
change.

Rust is the reference language; a concise TypeScript sketch
follows each Rust example to help alternate-language
implementers validate their own migration.

---

## 0.1.x → 0.2.0-alpha.1 (SPEC draft-03)

**Breaking at the signed-consent-body layer.** Envelope layout
(§1–§11) is unchanged; FRAME / INPUT / FRAME_LZ4 traffic is
still wire-compatible with any 0.1.x peer. Migration effort is
concentrated in four places:

1. Struct-literal constructions of the three signed `Core` types.
2. Pattern matches on `ConsentEvent`.
3. Call sites for `Session::observe_consent`.
4. Verify paths that previously called `ConsentRequest::verify`
   (etc.) directly.

You do NOT need to change anything at seal-path call sites that
don't touch consent, nor at `Session::new` / `Session::builder`
call sites.

### 1. Struct-literal `Core` constructions

The three signed bodies each gained a mandatory 32-byte
`session_fingerprint`. The canonical field order is normative
(SPEC §12.3) — do not reorder.

**Before (0.1.x):**

```rust
use xenia_wire::consent::{ConsentRequest, ConsentRequestCore, ConsentScope};

let core = ConsentRequestCore {
    request_id: 7,
    requester_pubkey: tech_sk.verifying_key().to_bytes(),
    valid_until: 1_700_000_300,
    scope: ConsentScope::ScreenAndInput,
    reason: "ticket #1234".into(),
    causal_binding: None,
};
let request = ConsentRequest::sign(core, &tech_sk);
```

**After (0.2.0-alpha.1) — recommended via the Session helper:**

```rust
use xenia_wire::consent::{ConsentRequestCore, ConsentScope};

let core = ConsentRequestCore {
    request_id: 7,
    requester_pubkey: tech_sk.verifying_key().to_bytes(),
    session_fingerprint: [0; 32], // placeholder, overwritten below
    valid_until: 1_700_000_300,
    scope: ConsentScope::ScreenAndInput,
    reason: "ticket #1234".into(),
    causal_binding: None,
};
let request = session
    .sign_consent_request(core, &tech_sk)
    .expect("session has a key installed");
```

The `Session::sign_consent_*` helpers derive the fingerprint
from the session's current key + source_id + epoch + the core's
`request_id`, overwrite the placeholder, and sign. Do NOT hand-
fill the placeholder with a meaningful value and then call the
raw `ConsentRequest::sign` — the receiver's fingerprint check
will fail unless your value matches the HKDF derivation bit-for-
bit.

**After — manual derivation (if you can't use the helper):**

```rust
let fp = session
    .session_fingerprint(7)
    .expect("session has a key");
let core = ConsentRequestCore {
    request_id: 7,
    requester_pubkey: tech_sk.verifying_key().to_bytes(),
    session_fingerprint: fp,
    valid_until: 1_700_000_300,
    scope: ConsentScope::ScreenAndInput,
    reason: "ticket #1234".into(),
    causal_binding: None,
};
let request = ConsentRequest::sign(core, &tech_sk);
```

The same pattern applies to `ConsentResponseCore` (→
`Session::sign_consent_response`) and `ConsentRevocationCore`
(→ `Session::sign_consent_revocation`).

**TypeScript sketch (for alternate-language implementers):**

```ts
// HKDF-SHA-256 per SPEC §12.3.1.
const info = new Uint8Array(17);
info.set(sourceId /* 8 bytes */, 0);
info[8] = epoch;
const be = new DataView(info.buffer);
be.setBigUint64(9, BigInt(request_id), /* littleEndian = */ false);

const fingerprint = await hkdfSha256({
    salt: new TextEncoder().encode("xenia-session-fingerprint-v1"),
    ikm: sessionKey, // 32 bytes
    info,
    length: 32,
});

const core = {
    request_id,
    requester_pubkey,
    session_fingerprint: fingerprint, // 32 bytes, field order matters
    valid_until,
    scope,
    reason,
    causal_binding: null,
};
const signature = await ed25519.sign(bincodeV1Encode(core), signingKey);
```

### 2. `ConsentEvent` variants carry `{ request_id }`

Every event is now a struct-shape carrying the `request_id` of
the message it describes. The state machine uses it to
distinguish legitimate ceremony progression from protocol
violations (SPEC §12.6.1).

**Before:**

```rust
use xenia_wire::consent::ConsentEvent;

session.observe_consent(ConsentEvent::Request);
session.observe_consent(ConsentEvent::ResponseApproved);
```

**After:**

```rust
use xenia_wire::consent::ConsentEvent;

session
    .observe_consent(ConsentEvent::Request { request_id: 7 })?;
session
    .observe_consent(ConsentEvent::ResponseApproved { request_id: 7 })?;
```

On the send side, you know `request_id` because you just picked
it. On the receive side, pull it from the deserialized core:
`ConsentEvent::Request { request_id: received_req.core.request_id }`.

### 3. `observe_consent` now returns `Result`

Legal transitions and benign no-ops return `Ok(state)`; protocol
violations (RevocationBeforeApproval, ContradictoryResponse,
StaleResponseForUnknownRequest) return
`Err(ConsentViolation)`. On violation the session state is NOT
mutated; the caller's contract is to tear down the session.

**Before:**

```rust
let state = session.observe_consent(ConsentEvent::Request);
```

**After:**

```rust
use xenia_wire::consent::ConsentViolation;

match session.observe_consent(ConsentEvent::Request { request_id: 7 }) {
    Ok(state) => { /* continue */ }
    Err(ConsentViolation::RevocationBeforeApproval { request_id }) => {
        // Hard fault — peer is broken or compromised. Tear down.
        return Err(MyAppError::PeerMisbehaved(request_id));
    }
    Err(ConsentViolation::ContradictoryResponse { request_id, prior_approved, new_approved }) => {
        // User tried to change their mind via a contradictory
        // Response; the correct primitive is Revocation. Log +
        // tear down; the peer's state machine is broken.
        return Err(MyAppError::ContradictoryConsent { request_id });
    }
    Err(ConsentViolation::StaleResponseForUnknownRequest { request_id }) => {
        return Err(MyAppError::StaleConsent(request_id));
    }
}
```

`ConsentViolation` implements `std::error::Error` via
`thiserror`, so `?`-propagation works if your error type
implements `From<ConsentViolation>` (or just map it).

### 4. Prefer `Session::verify_consent_*` over raw `.verify()`

`ConsentRequest::verify` (etc.) still exists and still checks
the Ed25519 signature. But it does NOT check the session
fingerprint — that's specific to the receiver's session state,
which the raw method doesn't have access to. The draft-03
verification contract (SPEC §12.3) requires BOTH checks.

**Before:**

```rust
if received_req.verify(Some(&expected_pubkey)) {
    // OK
}
```

**After:**

```rust
if session.verify_consent_request(&received_req, Some(&expected_pubkey)) {
    // OK — signature + fingerprint + pubkey all check out
}
```

The `Session::verify_consent_*` helpers transparently probe
both the current AND previous session keys for the fingerprint
compare, so a consent message signed just before rekey still
verifies during the grace window (added in 0.2.0-alpha.2; if
you're targeting alpha.1, the probe is current-key-only).

If you need only signature verification for an external audit
log — and you don't have access to the signing session — the
raw `.verify()` is still the right call. The draft-03
fingerprint is only checkable with the session key; an auditor
without it can still validate the pubkey-to-signature binding.

### 5. Test vector regeneration

If you pinned against vectors 07/08/09 from 0.1.x, their bytes
changed — the signed body's canonical encoding gained
`session_fingerprint`. Regenerate with:

```console
$ cargo run --example gen_test_vectors --all-features
```

The fingerprint value for vectors 07/08/09 under the fixture
key is `5b94fb75dd4d499825c7f26f32dea7dce067d59a5200584a2c9d7d9e18dfd7d4`
— same across all three (shared session + same `request_id=7`).
Alternate-language implementations that regenerate the
fingerprint locally under the fixture key MUST match that hex.

Vectors 10 / 11 / 12 are new event-sequence fixtures for the
three `ConsentViolation` variants. Format documented in
`test-vectors/10_revocation_before_approval.txt`.

---

## 0.2.0-alpha.1 → 0.2.0-alpha.2

No API break. Two receiver-side improvements:

1. `Session::verify_consent_*` now transparently probes the
   **previous** session key for the fingerprint compare. A
   consent message signed moments before a rekey (in flight
   during the grace window) now verifies correctly; previously
   it would false-reject. No code change required on integrator
   side — the behavior change is internal to the verify path.
2. SPEC §12.8 documents the timing-channel assumption on the
   verify pipeline (bincode deserialize + Ed25519 verify +
   constant-time fingerprint compare). Alternate-language
   implementers SHOULD audit their equivalents.
3. Event-sequence test vectors 10/11/12 ship for the three
   `ConsentViolation` variants.
4. A cargo-fuzz target `fuzz_observe_consent` is added to
   exercise the transition table under adversarial input.

No migration needed; just bump the dep.

---

## Older transitions (reference)

### 0.1.0-alpha.4 → 0.1.0-alpha.5 (SPEC draft-02r2)

Covered in full in `CHANGELOG.md`. Summary:

- `ConsentState::Pending` split into `LegacyBypass` (default
  for `Session::new`, sticky) and `AwaitingRequest` (opt-in via
  `SessionBuilder::require_consent(true)`). Exhaustive matches
  on `ConsentState` gain two new arms.
- New `SessionBuilder` at `Session::builder()`.
- Replay window now parameterized via
  `SessionBuilder::with_replay_window_bits(bits)` — valid
  values 64, 128, 256, 512, 1024. Default remains 64.

### 0.1.0-alpha.3 → 0.1.0-alpha.4

Pure reference-impl bug fix (per-key-epoch replay window,
issue #5). No API change. See `CHANGELOG.md` 0.1.0-alpha.4
entry for the bug details.
