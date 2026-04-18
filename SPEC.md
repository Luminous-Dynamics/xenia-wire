# Xenia Wire Protocol — Specification draft-02r1

> **Status**: draft-02r1 (2026-04-18 clarifying revision of draft-02).
> Corresponds to `xenia-wire 0.1.0-alpha.3` on crates.io. No wire-format
> changes from draft-02; revisions are clarifications that address
> ambiguities identified in first-round informal cryptographic review.
> See Appendix B for the full change list.
>
> Pre-alpha — the format is subject to breaking change in subsequent
> drafts. Reviewers: please open an issue for any remaining ambiguity;
> the spec is the normative reference, not the Rust source.
>
> **Document conventions**: The key words MUST, MUST NOT, REQUIRED,
> SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL
> are to be interpreted as described in [RFC 2119].
>
> [RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119

---

## 1. Introduction

### 1.1 Purpose

Xenia Wire is a binary envelope protocol for sealing application
payloads with authenticated encryption, protecting against replay,
and supporting key rotation without in-flight message loss. It is
designed for remote-control streams — screen frames, input events,
control messages — where two peers share a symmetric key established
out-of-band and exchange short messages at high frequency.

The name *Xenia* (ξενία) is the ancient Greek covenant between guest
and host; a technician is a guest in a client's machine, and the
protocol codifies the terms of that hospitality cryptographically.

### 1.2 Goals

- **Confidentiality** of payload contents against an on-path attacker
  who does not possess the session key.
- **Integrity + authenticity**: any modification to a sealed envelope
  is detected.
- **Replay resistance**: a captured envelope cannot be successfully
  opened a second time, even on an idempotent stream.
- **Stream isolation**: a single session key can seal multiple
  concurrent streams (forward frames, reverse inputs, control
  channels) without nonce collision.
- **Rekey without loss**: a sender can rotate keys mid-stream and
  the receiver continues to open in-flight envelopes sealed under
  the previous key for a bounded grace window.
- **Transport agnosticism**: the wire makes no assumption about
  transport — TCP, WebSocket, QUIC, UDP, and offline file carriage
  are all acceptable.

### 1.3 Non-goals

- **Not a handshake**: the session key arrives from an outer layer.
  `xenia-wire 0.1.x` assumes the key is installed directly. A
  forthcoming companion spec (Track 2.5 in the Luminous Dynamics
  research roadmap) specifies ML-KEM-768 + Ed25519 establishment.
- **Not TLS**: no certificate chain, no ALPN, no hostname binding,
  no cipher negotiation. The AEAD algorithm is fixed.
- **Not a general AEAD library**: the nonce layout and replay
  semantics are specific to replay-protected streams.
- **Not a framing protocol at the transport layer**: the envelope
  is a single opaque byte string; the transport is responsible for
  delimiting it.

### 1.4 Version

This document specifies **draft-02** of the wire protocol. The spec
version is independent of the `xenia-wire` crate version; the mapping
from crate version to wire draft is recorded in Appendix B.

### 1.4.1 Draft compatibility

Draft-02 is **additive** over draft-01: sections 1–11 describe the
same wire as draft-01 with clarifying edits only; section 12 is
new in draft-02 and introduces the consent ceremony.

| Range of sections | Wire-level compatibility |
|-------------------|-------------------------|
| §1 – §11 (core wire) | Unchanged from draft-01. A draft-01 receiver and a draft-02 sender interoperate for application `FRAME` / `INPUT` / `FRAME_LZ4` payloads. |
| §12 (consent ceremony) | New in draft-02. A draft-01 receiver that encounters payload types `0x20`/`0x21`/`0x22` treats them as unknown-reserved per §4.3 — the wire accepts them, but the application layer above draft-01 will not process them meaningfully. |

### 1.4.2 When to bump the draft

Breaking changes to any of the following MUST bump the draft version:

- Envelope layout or field order.
- Nonce construction.
- AEAD algorithm or associated-data handling.
- Replay-window semantics.
- Payload type registry reassignments (not additions).
- Canonical encoding of signed consent bodies (§12.3).

Adding new payload types in the reserved ranges (§4.2) or new
purely-additive consent fields with `Option<...>` defaults is not a
breaking change.

---

## 2. Wire format

Every sealed message is a single byte string called an *envelope*:

```
+--------+--------------+------+
| nonce  | ciphertext   | tag  |
| 12 B   | variable     | 16 B |
+--------+--------------+------+
```

The ciphertext is ChaCha20-Poly1305 encryption of the application
plaintext. The tag is the 16-byte Poly1305 authentication tag that
the AEAD construction produces. No length prefix is included — the
envelope's total length is determined by the transport.

**Associated data (AAD)**: draft-02 uses the empty byte string as
AEAD associated data. The nonce alone carries the context that
would otherwise live in AAD (`source_id`, `payload_type`, `epoch`,
`sequence`). A future draft MAY define non-empty AAD to bind
additional context (e.g. a session fingerprint derived from the
handshake); any such change is a breaking wire-format bump per
§1.4.2.

Minimum envelope length: **28 bytes** (12 nonce + 0 ciphertext + 16
tag). An envelope shorter than 28 bytes MUST be rejected by the
receiver without attempting to decrypt.

---

## 3. Nonce construction

The 12-byte nonce is the critical security-sensitive field. It MUST
be constructed as follows:

```
  byte offset:  0 1 2 3 4 5  6             7        8  9  10 11
              +-----------+ +-----------+ +------+ +------------+
              | source_id | | pld_type  | |epoch | |  sequence  |
              +-----------+ +-----------+ +------+ +------------+
               6 bytes       1 byte        1 byte   4 bytes (LE u32)
```

- **`source_id`** (bytes 0..6): exactly **6 bytes** of a per-session
  uniformly-random identifier on the wire. Generated once when the
  session is constructed and held stable for the session's lifetime
  (including across rekeys). The 6 wire bytes MAY be derived from
  any uniformly-random source of 48 bits or more; the Rust reference
  happens to generate 8 random bytes and truncate to the low 6, but
  alternative implementations storing only 6 bytes are equivalent
  for interop purposes.

- **`pld_type`** (byte 6): the payload type, which identifies the
  logical stream. See §4 for registry. A given
  `(source_id, pld_type)` tuple defines an independent replay
  window; see §5.

- **`epoch`** (byte 7): a per-session random epoch byte. Generated
  once at session construction. Provides domain separation between
  sessions that — by accident or adversarial intent — share both
  a session key and a `source_id`.

- **`sequence`** (bytes 8..12): a 32-bit unsigned integer,
  **little-endian**, taken from the low 32 bits of a single
  session-global monotonic counter maintained by the sender.

  > **Clarification of counter scope** (draft-02r1): the counter is
  > **session-global, not per-stream**. The sender maintains one
  > monotonic `nonce_counter` shared across all `pld_type` values.
  > The replay windows on the receive side are keyed by
  > `(source_id, pld_type)` per §5, which gives independent
  > per-stream replay semantics — but the counter itself does not
  > have to be per-stream because the `pld_type` byte in the nonce
  > already prevents nonce collision between streams. A stream that
  > receives `seq=5` on `FRAME` (`0x10`) and later `seq=5` on
  > `INPUT` (`0x11`) is operating correctly; the nonces differ at
  > byte 6.

  The counter starts at `0` when a key is installed and increments
  by 1 on each seal. It resets to `0` on rekey (see §6.4).

### 3.1 Uniqueness requirement

For a given session key, each nonce MUST be unique. A nonce reuse
under ChaCha20-Poly1305 catastrophically breaks confidentiality and
integrity (the same key-nonce pair encrypting two plaintexts yields
the key from the XOR of the ciphertexts).

The nonce layout ensures uniqueness as long as:

1. `source_id` is random per session (prevents cross-session
   collision at the same key).
2. `epoch` is random per session (further defense against accidental
   `source_id` collision).
3. The session-global `sequence` counter is monotonic on the sender.
4. The 32-bit sequence does not wrap under a single key.
   Implementations MUST enforce this boundary. Concretely:
   - Valid sequence values encoded in the nonce are the 2³²
     distinct values in `0..=2³²-1`.
   - Sealing a payload that consumes sequence `2³²-1` (the maximum
     representable value) is **permitted**.
   - An attempt to seal with a sender counter at or above `2³²`
     (which would produce the 2³²+1-th seal under the current key)
     MUST fail with `SequenceExhausted` (§9) **before nonce
     construction or AEAD invocation**. The reference implementation
     checks `nonce_counter >= 2³²` prior to sealing.

   At 30 frames per second the boundary is ~4.5 years of continuous
   operation under a single key; at 30 kHz it is ~40 hours. Real
   sessions rekey every ~30 minutes and reset the counter (§6.4),
   so the boundary is only reachable by a caller that has disabled
   or failed to trigger rekey.

### 3.2 Worked example

From test vector 01 (`test-vectors/01_hello_frame.envelope.hex`):

```
source_id = first 6 bytes of "XENIATST" (fixture label) = 58 45 4e 49 41 54
pld_type  = 0x10  (FRAME)
epoch     = 0x42
sequence  = 0     (first seal, encoded as 00 00 00 00)

nonce     = 58 45 4e 49 41 54 10 42 00 00 00 00
```

(The full 8-byte label `"XENIATST"` is a test-vector convenience
for human readability; only the 6 wire bytes `58 45 4e 49 41 54`
enter the nonce.)

The full envelope opens with this nonce and the fixture key to
produce the bincode-encoded `Frame` shown in
`test-vectors/01_hello_frame.input.hex`.

---

## 4. Payload type registry

The `pld_type` byte in nonce position 6 identifies the logical
stream. Two envelopes with different payload types never collide
on the replay window, and — because the payload type is part of
the nonce — never collide on the AEAD nonce stream either.

### 4.1 Assigned values

| Value | Symbol | Direction | Description |
|-------|--------|-----------|-------------|
| `0x10` | `FRAME` | forward (server → client) | Primary stream: application frames. |
| `0x11` | `INPUT` | reverse (client → server) | Reverse path: input events. |
| `0x12` | `FRAME_LZ4` | forward | LZ4-compressed-before-seal frame. See §7. |

### 4.2 Reserved ranges

| Range | Owner | Status |
|-------|-------|--------|
| `0x00..=0x0F` | Upstream mesh layer | Reserved for interop with the Symthaea mesh primitives. Do NOT use. |
| `0x13..=0x1F` | `xenia` core | Reserved for future core stream types. |
| `0x20..=0x2F` | `xenia` extensions | Consent ceremony `0x20`/`0x21`/`0x22` assigned in draft-02 (§12); attestation-chained action log `0x23` reserved. `0x24..=0x2F` reserved for future draft-level extensions. |
| `0x30..=0xFF` | applications | Free for caller-defined payload types. No IANA-style coordination — pick one and document it locally. |

### 4.3 Discarding unknown payload types

A receiver that opens an envelope with a `pld_type` it does not
recognize SHOULD treat the plaintext as opaque bytes and either
dispatch to a catch-all handler or drop the envelope. It MUST NOT
panic or terminate the session. Forward-compatibility in the
`0x13..=0x2F` range is intentional: a sender on a newer draft can
mix new payload types into a stream that an older-draft receiver
participates in.

> **Exception for consent payloads** (`0x20`/`0x21`/`0x22`, §12):
> a draft-01 receiver that does NOT implement the consent ceremony
> MAY still receive these payload types. A security-conscious
> application-layer deployment SHOULD configure the receiver to
> drop all application `FRAME` / `INPUT` / `FRAME_LZ4` payloads on
> any session where a `ConsentRequest` was observed but the
> ceremony was not completed — treating unimplemented-consent the
> same as "consent required but not approved" rather than as
> "no consent system in use." This is a receiver-side policy
> choice, not a wire-level requirement.

---

## 5. Replay window

### 5.1 Semantics

The receiver maintains, per `(source_id, pld_type)` tuple, a
64-bit sliding window over received sequence numbers. The window
tracks:

- `highest`: the highest sequence seen so far on this stream.
- `bitmap`: a 64-bit mask where bit `i` indicates sequence
  `highest - i` has been received (bit 0 = highest).

An incoming envelope with sequence `seq` is accepted if and only
if:

1. The window has not yet been initialized for this stream
   (first-seen case: accept and initialize `highest = seq`,
   `bitmap = 1`), OR
2. `seq > highest` (strictly new high: shift the bitmap left by
   `seq - highest` bits, set bit 0, update `highest`), OR
3. `highest - seq < 64` AND bit `(highest - seq)` of `bitmap` is
   unset (within-window, unseen: set the bit, accept).

Otherwise the envelope is rejected.

Sequences where `highest - seq >= 64` (more than 64 below the
current high) MUST be rejected outright — these are either replays
or late-delivery beyond tolerance.

### 5.2 Multi-stream independence

The replay window is keyed by `(source_id, pld_type)`. This means:

- A sender can interleave `FRAME` (0x10) and `INPUT` (0x11) on
  the same session, and neither stream's sequence progression
  affects the other.
- A sender can rotate `FRAME` (0x10) with `FRAME_LZ4` (0x12) on
  the same session, with independent windows.

### 5.3 Rekey interaction

> **Clarification (draft-02r1)**: the original text said "the replay
> window is NOT cleared on rekey" without specifying how a
> counter-reset sender and a highest-sequence-accumulating receiver
> should reconcile. The reviewed ambiguity is resolved here: replay
> state is scoped **per-key-epoch** on the receive side, NOT shared
> across rekey.

Replay state is keyed by a tuple `(source_id, pld_type, key_epoch)`
where `key_epoch` is a receiver-local counter that increments each
time the receiver installs a new session key. The `key_epoch` is
implementation-internal — it is NOT transmitted on the wire and
does NOT appear in the nonce. Its role is to keep the replay
window associated with the *key context* under which an envelope
was verified.

The receiver's open path is:

1. Verify the envelope's AEAD tag, trying `current_key` first and
   `prev_key` second if the first fails (within grace; §6.2).
2. Remember which key verified. Call that key's epoch `e`.
3. Apply the sliding-window check against the replay state keyed
   by `(source_id, pld_type, e)`.
4. If accepted, update that state.

**Why this shape**. The old-key and new-key streams use different
actual cryptographic nonces (different keys producing different
ciphertexts for any given plaintext + nonce structure), so they do
not share a nonce-uniqueness concern. What they share is the
higher-level protocol property: "no envelope bytes should open
twice." Scoping replay state per `key_epoch` keeps that property
intact:

- An attacker who replays an envelope sealed under the old key
  during the grace period is caught by the old-epoch window (which
  still has its full history).
- After the grace period expires, the old key is discarded (§6.3)
  and envelopes that would have opened under it can no longer open
  at all — replay defense is then complete by key absence.
- New envelopes sealed under the new key start against a fresh
  per-epoch window at `sequence = 0`, trivially accepted, no
  artifacts from the old-key sequence history.

**Interaction with the grace period**. During the rekey grace
window (§6.2), TWO per-epoch replay windows are live simultaneously
for the same `(source_id, pld_type)` stream: one for the current
key, one for the previous. Each envelope is routed to exactly one
of them based on which key verified its AEAD tag in step 2 above.
After the previous key expires (§6.3), the previous-epoch window
MAY be discarded.

**Reference implementation status**. As of `xenia-wire 0.1.0-alpha.4`
(2026-04-18) the reference implementation matches this specification:
`ReplayWindow::accept` takes `(source_id, payload_type, key_epoch, seq)`,
`Session` tracks `current_key_epoch` + `prev_key_epoch`, and
`Session::tick` reclaims old-epoch replay state when the previous
key's grace period expires. See
[issue #5](https://github.com/Luminous-Dynamics/xenia-wire/issues/5)
for the bug-fix history. `0.1.0-alpha.3` users SHOULD upgrade.

### 5.4 First-seen starting sequence

The window implementation does not require the first-seen
sequence to be `0`. A receiver that joins a stream in progress
(for example, after a transport reconnect where the sender has
already advanced its counter) accepts whatever sequence arrives
first as `highest`. Subsequent envelopes below `highest - 64`
are still rejected, above-window envelopes are still accepted,
etc. This makes the wire robust to sender-side reconnection
that does not reset the counter.

---

## 6. Key lifecycle

### 6.1 Installation

A session has no key initially. `Session::install_key(key)`
(Rust reference) installs a 32-byte ChaCha20-Poly1305 key. The
session's nonce counter resets to `0` on installation.

Before a key is installed, seal and open MUST fail:

- Seal returns a `NoSessionKey` error.
- Open returns a `NoSessionKey` error (or `OpenFailed` — both
  are acceptable; see §9).

### 6.2 Rekey

Subsequent calls to `install_key(new_key)` perform a rekey:

1. The existing key is moved to `prev_key`.
2. `prev_key_expires_at` is set to `now + rekey_grace` (default
   5 seconds; implementation-configurable).
3. The new key becomes current.
4. The nonce counter resets to `0`.

During the grace window, the receiver tries AEAD verification
with the current key first; if that fails, it tries the previous
key. This allows in-flight envelopes sealed under the old key to
continue opening successfully for the grace duration.

### 6.3 Previous-key expiry

After the grace period elapses, the previous key MUST be discarded
from receiver-side state. A receiver that retains the previous key
indefinitely reopens the window for cross-rekey replay and defeats
the forward-secrecy property that rekey provides.

The Rust reference exposes a `Session::tick()` method that the
caller invokes periodically to expire the previous key. An
implementation MAY instead expire inline on each open call —
either is acceptable as long as the expiry deadline is respected.

### 6.4 Nonce counter reset

The nonce counter resets to `0` on rekey. This is safe because
the AEAD nonce includes the `epoch` byte (unchanged across rekey)
and the per-session `source_id` — both of which are stable across
rekey — combined with a new key. The same nonce under a different
key produces a different ciphertext, so there is no nonce-reuse
attack across rekey.

---

## 7. LZ4-before-AEAD compression

### 7.1 Rule

When compression is used, it MUST be applied to the plaintext
BEFORE AEAD sealing, not after. The pipeline is:

```
application payload
  → serialize (bincode in the reference)
  → lz4 compression (length-prepended block)
  → ChaCha20-Poly1305 seal → envelope
```

### 7.2 Rationale

ChaCha20-Poly1305 ciphertext is pseudorandom by construction.
Applying any general-purpose compressor (LZ4, zstd, gzip) to
ciphertext achieves zero compression and wastes CPU. Compression
MUST therefore precede sealing.

The compression algorithm is LZ4 in its block format with a
length-prefixed size header (`lz4_flex::block::compress_prepend_size`
in the Rust reference). Decompression reads the 4-byte little-endian
length prefix and decompresses the following bytes.

### 7.3 Payload-type separation

Compressed and uncompressed frames use distinct payload types
(`FRAME` = 0x10 vs `FRAME_LZ4` = 0x12). This means:

- The receiver knows from the nonce byte 6 whether to attempt
  decompression.
- The two streams have independent replay windows, so a sender
  can interleave raw and compressed frames on the same session
  key without collision.
- Receiving a `FRAME_LZ4` envelope with `open_frame` (the non-LZ4
  opener) fails cleanly — the bincode-deserialize step rejects
  the LZ4 block header as malformed bincode.

### 7.4 Empirical basis

On live Pixel 8 Pro traffic (2026-04-17, scrcpy HEVC → `Frame`
payload), LZ4-before-seal produced a **2.12× overall bandwidth
reduction** and **2.20× on steady-state Delta frames** compared
to the raw-seal baseline. At 30 fps the raw path is 18.35 MB/s;
LZ4 path is 8.34 MB/s — margin of 5% under the 8.75 MB/s
network-friendly gate. See the Luminous Dynamics roadmap v1.7
(Phase II.A) for the measurement harness.

### 7.5 Compression side-channel considerations

Classic compression-plus-encryption side channels (CRIME 2012,
BREACH 2013) apply when (a) an attacker can influence part of the
plaintext, (b) the attacker-influenced part is compressed in the
same block as an unknown secret, and (c) the attacker can observe
the resulting ciphertext length across many queries. Xenia's
typical payload — captured screen frames + input events — does not
match this shape cleanly:

- **Video frames** are mostly secret screen content with no
  attacker-influenced adjacency; compression side channels are not
  a meaningful concern for this workload.
- **Structured protocol messages with mixed attacker-controlled
  and secret material** (e.g., authenticated web sessions with
  cookies adjacent to attacker-submitted form fields) DO match the
  CRIME/BREACH shape. If a deployment puts such payloads through
  the `FRAME_LZ4` path, it MUST assess the side-channel risk.

Implementations and deployments SHOULD:

- Use `FRAME` (raw AEAD) not `FRAME_LZ4` for payloads that mix
  attacker-controlled and secret material in the same envelope.
- Enforce a per-message decompression output limit (the reference
  implementation caps at 16 MiB, matching the transport's
  envelope cap). A decompression bomb that inflates to GBs should
  be rejected before allocation, not after.
- Treat compression as a bandwidth optimization, not a security
  property.

The AEAD tag authenticates the compressed (pre-AEAD) bytes, so
tampering with the compressed form to produce a decompression
bomb is prevented — but a peer with the session key can still
send a legitimately-sealed envelope whose decompressed size is
unreasonably large. The output cap defends against that case.

---

## 8. Handshake (placeholder)

### 8.1 Out of scope

The handshake is NOT specified in draft-01. `xenia-wire 0.1.x`
assumes the 32-byte session key is established by an outer layer
and installed via `Session::install_key`. In tests and early
prototypes a shared fixture key is acceptable; in production
deployments the key MUST come from a real key-exchange protocol.

### 8.2 Planned future: ML-KEM-768 + Ed25519

A companion specification — currently tracked as "Track 2.5" in
the Luminous Dynamics research roadmap — will define a
post-quantum-resistant handshake:

- **Identity**: Ed25519 signing keys on both peers, with
  application-defined trust anchors.
- **Key encapsulation**: ML-KEM-768 (NIST PQC winner) producing
  a 32-byte shared secret.
- **Session key derivation**: HKDF-SHA-256 over the shared secret
  with a protocol-specific salt and info label.
- **Rekey**: asynchronous re-handshake on a timer or on explicit
  request.

Until that spec lands, each deployment is responsible for its
own key establishment, and cross-implementation interop on the
handshake is undefined.

---

## 9. Error taxonomy

The Rust reference exposes a `WireError` enum with four variants.
An interoperable implementation SHOULD map its own errors onto
this taxonomy.

| Variant | Meaning | Caller response |
|---------|---------|-----------------|
| `Codec(msg)` | Payload serialization / deserialization failed. | Drop the envelope. Log `msg` in debug builds. Keep the session alive. |
| `NoSessionKey` | Seal or open attempted before a key was installed. | Install a key before retrying. Programming error if it occurs on an active session. |
| `SealFailed` | The underlying AEAD implementation rejected the seal inputs. Should not occur with a valid 32-byte key. | Treat as a bug; investigate. |
| `OpenFailed` | AEAD verification failed (wrong key, tampered ciphertext, truncated envelope, or the replay window rejected a valid-ciphertext duplicate). | **Drop the envelope and keep the session alive.** Do NOT distinguish sub-cases in production — finer diagnosis leaks timing or structure to an attacker. |
| `SequenceExhausted` | Sender's nonce counter has reached `2^32`. The next seal would cause catastrophic nonce reuse. | **Rekey before sealing again.** Install a new session key (which resets the counter to `0`); any envelopes still in flight under the old key continue to open during the grace period (§6.2). Failing here is a programming error: the caller disabled or failed to trigger rekey on the configured cadence. |

### 9.1 Important: don't leak sub-case distinctions

An AEAD-verification failure, a replay-window rejection, and a
length-check failure all surface as `OpenFailed`. This is
deliberate. A receiver that logs or signals back the specific
reason allows an attacker to map out the replay-window boundary,
perform timing analysis on AEAD verify vs. replay check, and
tailor probe traffic.

**Scope of the prohibition** (draft-02r1 clarification):

- **Remote / on-wire**: implementations MUST NOT distinguish
  `OpenFailed` sub-cases to the peer. No error codes, no timing
  differences, no side-channel signals.
- **Local observability**: implementations MAY maintain local
  diagnostic counters and logs that distinguish sub-cases
  (`aead_fail_count`, `replay_reject_count`, `too_short_count`,
  etc.) for operator telemetry. These local distinctions MUST NOT
  be reflected back to the peer.

This distinction matters in production. An operator needs to know
whether their receivers are being battered by replay attempts or
tag-tampered envelopes — those debug very differently. Forbidding
local observability would be an over-correction that hurts
operational triage without helping security.

---

## 10. Security properties

Assuming:

- The session key is a uniformly random 256-bit secret unknown
  to the attacker.
- `source_id` and `epoch` are uniformly random at session setup.
- The nonce counter is monotonic per stream.

Xenia Wire provides:

### 10.1 Confidentiality

ChaCha20-Poly1305 with a 32-byte key and 12-byte nonce achieves
IND-CCA2 security in the multi-user setting. Payload contents
are indistinguishable from random to an attacker without the key.

### 10.2 Integrity and authenticity

Poly1305 provides a 16-byte authentication tag. Any modification
to the envelope (nonce bytes, ciphertext, or tag) causes the tag
to fail verification. The attacker's forgery probability per
attempt is bounded conservatively by `8L / 2^106` where `L` is the
number of 16-byte blocks in the authenticated data (per Bernstein's
Poly1305-AES analysis, transferable to ChaCha20-Poly1305). For the
envelope sizes this wire carries (a few KB to a few MB), that
bound is effectively `2^-100` to `2^-90` per attempt; the "~2^-100"
rounding in earlier drafts was accurate to one significant figure
but the precise bound depends on message length.

### 10.3 Replay resistance

The 64-slot sliding replay window (§5) rejects:

- Exact duplicates within the window.
- Too-old envelopes (more than 64 below the current high).

Combined with the monotonic nonce sequence, this means an attacker
cannot successfully inject a previously-captured envelope.

### 10.4 Forward secrecy via rekey

A key compromise of the current session key reveals all envelopes
sealed under that key. Regular rekey (§6) limits the damage to
the ~30-minute window between rotations. Envelopes sealed under
an expired previous key are not recoverable if the attacker
obtained only the current key.

**Note**: true forward secrecy requires the *handshake* to also
be forward-secret (per-session ephemeral keys), which is the
responsibility of the future ML-KEM handshake spec, not of this
document.

### 10.5 Domain separation

The `pld_type` byte in the nonce prevents nonce collision between
concurrent streams on the same session key. Two streams can
independently advance their sequence counters without colliding
on the AEAD nonce namespace.

### 10.6 Known non-properties

- **No traffic analysis protection**: envelope length reveals
  plaintext length (plus a constant overhead for nonce and tag);
  an attacker observing the wire learns the size of sealed
  payloads and their arrival times.
- **No identity hiding**: `source_id` and `epoch` are in plaintext
  in the nonce. They are random and do not carry out-of-band
  identity, but they are stable per session and allow an on-path
  observer to group envelopes by originating session.
- **No denial-of-service protection**: an attacker who can reach
  the receiver can send arbitrary bytes. The receiver's AEAD
  verification + replay window check is cheap (~1 μs per open),
  so DoS resistance is delegated to the transport (rate limiting,
  connection caps).
- **No post-quantum confidentiality of PAST traffic** if the
  session key is compromised via a future quantum break of the
  handshake. ML-KEM-768 (Track 2.5) is intended to close this,
  but draft-01 does not address handshake confidentiality.

---

## 11. Non-goals (restated)

- **TLS replacement** — no certificate chain, no ALPN, no
  hostname binding. Use TLS where TLS is appropriate.
- **MSP workflow** — consent ceremony (draft-02, §12) is the
  wire's contribution to the workflow; session recording and
  attestation-chained action logs remain future work.
- **General AEAD library** — the nonce layout is specific to
  replay-protected streams; don't use the envelope format for
  unrelated purposes.
- **Transport framing** — the envelope is a single byte string.
  Delimiting it on the wire (length prefix, WebSocket binary
  frame, QUIC stream boundary) is the transport's job.

## 12. Consent ceremony (draft-02)

### 12.1 Purpose

A remote-control session that lets a technician read screen content
and inject input events must be authorized by the user whose machine
is being accessed. The consent ceremony is Xenia's wire-level
primitive for that authorization:

1. A requester (technician) seals a signed `ConsentRequest` describing
   what is being asked for and for how long.
2. A responder (end-user) seals a signed `ConsentResponse` approving
   or denying.
3. Either party MAY seal a signed `ConsentRevocation` at any point
   after approval, asymmetrically terminating the session.

Each message carries an Ed25519 signature separate from the AEAD
tag. The AEAD protects confidentiality and replay; the signature
provides a **third-party-verifiable signed consent artifact**:
the signed body survives disclosure of the session key, so an
auditor holding only the plaintext + the signer's public key can
confirm the signature was produced by the claimed pubkey-holder.

> **On "non-repudiation"** (draft-02r1): earlier drafts used the
> phrase *non-repudiation*. That term has a contested legal
> history and typically requires a binding between the signing
> key and a human identity, which this wire deliberately does not
> provide (§12.8). The weaker but honest claim — "third-party
> verifiable" — is what the signature actually delivers. Deployments
> that need enforceable non-repudiation MUST layer an identity-to-
> pubkey binding above this wire (e.g. an MSP attestation chain,
> trust anchor provisioned via out-of-band process).

### 12.2 Payload types

Introduced by this draft:

| Value | Symbol | Description |
|-------|--------|-------------|
| `0x20` | `CONSENT_REQUEST` | Requester → Responder |
| `0x21` | `CONSENT_RESPONSE` | Responder → Requester |
| `0x22` | `CONSENT_REVOCATION` | Either party → Counterparty |

All three are sealed via the normal AEAD path (§3) and are subject
to the replay window (§5) on their own `(source_id, pld_type)`
keys — independent from application `FRAME` / `INPUT`.

### 12.3 Message structure

#### ConsentRequest

Plaintext (before bincode encoding) is:

```
ConsentRequest {
  core: ConsentRequestCore {
    request_id: u64,                       // correlation id
    requester_pubkey: [u8; 32],            // Ed25519 public key
    valid_until: u64,                      // Unix epoch seconds
    scope: ConsentScope,                   // enum, see §12.4
    reason: String,                        // free-text justification
    causal_binding: Option<CausalPredicate>, // MUST be None in draft-02
  },
  signature: [u8; 64],                     // Ed25519 over bincode(core)
}
```

The signature covers `bincode::serialize(&core)` — NOT the sealed
envelope. This lets a third-party auditor verify the consent using
only the plaintext and the public key, without the session key.

**Verification contract**: to verify `ConsentRequest.signature`, the
verifier MUST (a) deserialize `core` from the received plaintext,
(b) re-serialize `core` using the exact same canonical encoding
(§12.3.1), (c) verify the Ed25519 signature over that re-serialized
byte sequence using `core.requester_pubkey`. Any deviation in the
re-encoding — byte order, integer width, string length prefix
format — will produce a signature mismatch.

#### 12.3.1 Canonical encoding requirement (load-bearing)

The signature mechanism is only as strong as the agreement between
sender and receiver on the canonical encoding of `core`. This
subsection specifies the canonical encoding explicitly.

In draft-02, the canonical encoding of `core` is **bincode v1 with
its default configuration**, specifically:

- Little-endian byte order.
- Fixed-int encoding for integer types (`u32` → 4 bytes,
  `u64` → 8 bytes; NOT varint).
- Sequence length prefix: `u64` little-endian (for `Vec`, `String`
  inside `core`).
- No size limit beyond ambient memory.
- No trailing bytes.

**Bincode v2 is NOT compatible.** Bincode v2's `encode_to_vec`
defaults to varint-encoded integers and a different length-prefix
width. A v2-generated signature will fail v1 verification and vice
versa. Implementations MUST pin to bincode v1 (or a canonical
re-implementation of v1's byte format).

**Known limitation — dependency coupling.** Binding a normative
signature format to a specific Rust crate's byte layout is fragile
over long timescales. A future draft is expected to specify a
library-independent canonical encoding (likely a minimal fixed-
width TLV format) that decouples verification from bincode.
Draft-02 accepts the coupling as technical debt to ship; fixing
it is tracked as a v1.0-blocker design item.

Test vectors for all three consent message types (`07_consent_request`,
`08_consent_response`, `09_consent_revocation` in `test-vectors/`)
exercise the exact canonical byte sequence under bincode v1 so
alternate-language implementations can validate against known-good
output.

#### ConsentResponse

```
ConsentResponse {
  core: ConsentResponseCore {
    request_id: u64,                // matches the request being answered
    responder_pubkey: [u8; 32],     // Ed25519 public key
    approved: bool,
    reason: String,                 // empty on approval; explanation on denial
  },
  signature: [u8; 64],
}
```

#### ConsentRevocation

```
ConsentRevocation {
  core: ConsentRevocationCore {
    request_id: u64,                // references the approved request
    revoker_pubkey: [u8; 32],       // either party's public key
    issued_at: u64,                 // Unix epoch seconds
    reason: String,
  },
  signature: [u8; 64],
}
```

### 12.4 ConsentScope

Scope is advisory — the wire does not enforce what the technician
actually transmits. Application-level policy MUST match traffic
against the active scope.

| Value | Name | Meaning |
|-------|------|---------|
| `0` | `ScreenOnly` | View only; input SHOULD be ignored. |
| `1` | `ScreenAndInput` | View + input events. |
| `2` | `ScreenInputFiles` | View + input + file transfer. |
| `3` | `Interactive` | View + input + files + shell. |

Additional scope values MAY be defined in future drafts. Unknown
scope values SHOULD be treated as the most restrictive interpretation
the receiver understands.

**Enforcement responsibility**: the wire enforces `ConsentScope`
at the *coarse* level of allowing or denying application
`FRAME` / `INPUT` / `FRAME_LZ4` traffic altogether (per §12.7).
It does NOT inspect frame contents to verify the scope. If a
`ConsentRequest` declared `ScreenOnly` but the technician starts
injecting input events, the wire will happily carry them — the
application layer MUST check the active `ConsentScope` against
the event type on every frame. The wire gate is a necessary but
not sufficient condition for scope compliance.

### 12.5 Reserved: causal_binding

`ConsentRequest.causal_binding` MUST be `None` in draft-02. The
field is reserved for a forthcoming Ricardian-contract extension
that binds the consent to external causal state ("authority valid
while ticket #1234 is In-Progress") evaluated at each frame against
a decentralized truth-source. Receivers that do not understand the
predicate MUST reject the request as malformed.

### 12.6 Session state machine

Every session SHALL track consent state:

```
  ┌─────────┐  observe Request   ┌──────────┐
  │ Pending │ ─────────────────▶ │ Requested │
  └─────────┘                    └──────────┘
       │                              │
       │                              │ observe Response{approved=true}
       │                              ▼
       │                         ┌──────────┐
       │                         │ Approved │◀──┐
       │                         └──────────┘   │
       │                              │         │
       │                              │         │ (Approved is stable
       │                              │         │  until revocation)
       │                              │         │
       │                              │ observe Revocation
       │                              ▼
       │                         ┌──────────┐
       │                         │ Revoked  │
       │                         └──────────┘
       │
       │ observe Response{approved=false}
       ▼
  ┌────────┐
  │ Denied │ (from Requested)
  └────────┘
```

Driven by the caller (not the wire) after verifying each message.
Transitions not shown (e.g., Response from Pending, Revocation
from Pending) MUST be no-ops.

**Duplicate and conflict handling** (draft-02r1):

- A second `ConsentRequest` observed while state is `Requested`
  MAY update `request_id` / `valid_until` on the receiver side,
  or MAY be dropped — this is an application-policy choice not
  fixed by the wire. Implementations SHOULD document their chosen
  behavior.
- A second `ConsentResponse` for the same `request_id` that
  confirms the already-recorded decision MUST be a no-op.
- A second `ConsentResponse` for the same `request_id` that
  contradicts a prior decision (e.g. a `denied=false` after an
  `approved=true`) MUST be rejected as a protocol violation.
  Implementations MAY treat the contradiction as a policy signal
  to tear down the session.
- A `ConsentRevocation` observed after an earlier revocation MUST
  be a no-op (state already `Revoked`).
- `request_id` uniqueness is REQUIRED to be monotonic within a
  single `(source_id, ceremony)` pair on the requester side.
  Receivers MAY track active `request_id`s to correlate multiple
  concurrent requests, but the wire does not require more than
  the standard replay-window defense.

### 12.7 FRAME gating

When a session's consent state is `Requested`, `Denied`, or
`Revoked`, the receiver MUST NOT accept, and the sender MUST NOT
seal, payload types `0x10` / `0x11` / `0x12` (application `FRAME` /
`INPUT` / `FRAME_LZ4`). Attempts return:

- `ConsentRevoked` when state is `Revoked`.
- `NoConsent` otherwise.

When state is `Pending` or `Approved`, application payloads flow
normally.

> **On the `Pending` state's dual meaning** (draft-02r1): the
> `Pending` state is overloaded in draft-02. It conflates two
> operationally different situations:
>
> 1. **"Consent system not in use"** — a session that intends to
>    use an out-of-band consent mechanism (MSP pre-authorization,
>    deployment-level trust anchors) and will never run a Xenia
>    ceremony. Application traffic should flow unimpeded.
> 2. **"Awaiting request"** — a session that intends to use
>    Xenia's ceremony but has not yet seen a `ConsentRequest`.
>    A security-conscious deployment might want to block traffic
>    until the ceremony completes.
>
> The wire cannot distinguish these intent-level positions from
> the sequence of events it observes. The current rule — `Pending`
> allows traffic — matches interpretation (1) and is the correct
> default for backward compatibility with draft-01 deployments.
> Deployments that want interpretation (2) MUST either (a)
> configure the receiver to require a `ConsentRequest` before
> opening any application payload, enforced at the application
> layer above the wire, or (b) wait for a future draft that
> introduces distinct states (tentatively named `LegacyBypass`,
> `AwaitingRequest`, `Requested`, ...).
>
> Splitting `Pending` into richer states is tracked as a
> post-draft-02 design item.

### 12.8 Security properties

- **Third-party verifiable signed consent**: each consent decision
  is signed by a device key independently of the AEAD session. An
  auditor with the signed plaintext and the signer's public key
  can verify the signature was produced by the claimed pubkey-
  holder, without needing the AEAD key — appropriate for
  post-session compliance review. This is weaker than full
  legal non-repudiation, which also requires a binding between
  the signing pubkey and a human identity; that binding is out
  of scope for this wire (see §12.10).
- **Binding to session is currently LOOSE** (draft-02r1): the
  consent signature does NOT cover the AEAD session key, nonce,
  or any session-unique material. A consent signed in session A
  is, by default, replayable as a valid signed artifact in
  session B with the same participants.

  This is a known design limitation, not a desired property.
  Deployments requiring session-binding SHOULD include a session
  fingerprint (e.g. HKDF-derived from the session key, or the
  first envelope's nonce) in `ConsentRequestCore.reason` as a
  free-text workaround. A future draft will add an explicit
  `session_binding: Option<[u8; 32]>` field to
  `ConsentRequestCore` so deployments don't have to smuggle
  binding material through the reason string.

  Tracked as a post-draft-02 design item.
- **No identity binding to humans**: the pubkey-to-human binding
  is out of scope. An MSP attestation chain (key signing by the
  employer) is a forthcoming extension.

### 12.9 Threats considered in this draft

- **Replayed ConsentRequest**: rejected by the replay window (§5) —
  the request's envelope carries a monotonic sequence like any other
  sealed message.
- **Forged ConsentResponse**: rejected by signature verification.
  The responder's public key is expected to match the key the
  application trusts for this user.
- **Bait-and-switch scope**: if the technician sends wider-scope
  traffic than approved, the receiver MUST drop the traffic.
  This is an application-level policy and not enforced by the wire.
- **Revocation race**: between the revocation being sealed and the
  counterparty observing it, the counterparty may still receive
  frames. The window is bounded by transport RTT + AEAD-open time.
  Applications that need harder termination SHOULD treat revocation
  as asynchronous best-effort and rely on transport teardown for
  hard termination.

### 12.10 Threats explicitly out of scope (draft-02)

- **Human-identity fraud**: a technician who controls an approved
  device key can act as that technician. Device-key-to-human binding
  is an organizational trust problem, not a wire problem.
- **Coerced consent**: if the user is under duress, they can still
  sign an approval. Wire-level consent does not detect coercion.
- **Clock skew attacks**: `valid_until` and `issued_at` are wall-
  clock dependent. Receivers SHOULD grant a bounded skew (±30s
  recommended) and SHOULD reject consent messages outside the
  sender's expected operating window.

---

## Appendix A. Test vectors

Six reference vectors ship in `test-vectors/` of the reference
implementation. All use a fixed key, `source_id`, and `epoch` so
an alternate implementation can reproduce every byte:

| # | Name | Exercises |
|---|------|-----------|
| 01 | `hello_frame` | Canonical roundtrip; 12-byte UTF-8 payload. |
| 02 | `input_pointer` | `pld_type=0x11` domain separation vs vector 01. |
| 03 | `empty_payload` | Zero-length plaintext. |
| 04 | `long_payload` | 256 bytes covering every byte value. |
| 05 | `nonce_structure` | Three sequential seals, seq counter increments. |
| 06 | `lz4_frame` | LZ4-before-AEAD pipeline. |

Fixed fixture parameters:

- `source_id` = `58 45 4e 49 41 54 53 54` (`"XENIATST"`; nonce
  consumes bytes 0..6).
- `epoch` = `0x42`.
- `key` = `"xenia-wire-test-vector-key-2026!"` (32 ASCII bytes,
  hex `78 65 6e 69 61 2d 77 69 72 65 2d 74 65 73 74 2d 76 65 63
  74 6f 72 2d 6b 65 79 2d 32 30 32 36 21`).

See `test-vectors/README.md` for file format and how to consume
from a non-Rust implementation.

---

## Appendix B. Version history

| Draft | Date | Crate version | Changes |
|-------|------|---------------|---------|
| draft-01 | 2026-04-18 | `0.1.0-alpha.1` / `alpha.2` | Initial publication. |
| draft-02 | 2026-04-18 | `0.1.0-alpha.3` | Adds §12 Consent Ceremony (payload types `0x20`/`0x21`/`0x22`). Requires Ed25519 signing. No breaking change to existing wire format — §1–§11 are unchanged. |
| **draft-02r1** | 2026-04-18 | `0.1.0-alpha.3` (spec revision, no crate bump) | Clarifying revision in response to first round of informal cryptographic review. No wire-format changes. Highlights: (a) §1.4 version-consistency fix; (b) explicit AAD=empty statement in §2; (c) `epch` → `epoch` naming cleanup; (d) `source_id` "6 bytes on wire, label may derive from 8-byte fixture" clarification; (e) explicit session-global counter semantics + tightened sequence-exhaustion boundary in §3; (f) per-key-epoch replay state in §5.3 (flags a reference-implementation gap to close); (g) compression side-channel subsection §7.5; (h) observability-local-vs-remote split in §9.1; (i) Poly1305 bound precision in §10.2; (j) canonical-encoding subsection §12.3.1; (k) third-party-verifiable-signed-consent terminology instead of "non-repudiation" throughout §12; (l) `ConsentScope` per-frame enforcement note; (m) duplicate/conflict handling on the consent state machine; (n) explicit discussion of the `Pending`-state dual-meaning design gap; (o) session-binding known-limitation flag. Four design-level items (session_binding field, richer consent states, duplicate semantics decision, configurable replay window size) tracked as post-draft-02 design issues. |

---

## Appendix C. References

- Bernstein, D. J. (2008). ChaCha, a variant of Salsa20.
  <https://cr.yp.to/chacha/chacha-20080128.pdf>
- Nir, Y. & Langley, A. (2018). RFC 8439 — ChaCha20 and Poly1305
  for IETF Protocols. <https://www.rfc-editor.org/rfc/rfc8439>
- Kent, S. (2005). RFC 4303 — IP Encapsulating Security Payload
  (ESP) — reference for the 64-bit sliding replay window design.
  <https://www.rfc-editor.org/rfc/rfc4303>
- National Institute of Standards and Technology (2024). FIPS 203
  — Module-Lattice-based Key-Encapsulation Mechanism Standard
  (ML-KEM).
- `lz4_flex` crate. <https://crates.io/crates/lz4_flex>
- Collet, Y. (2011). LZ4 frame format specification.
  <https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md>

---

*This specification is licensed under the same terms as
`xenia-wire`: Apache-2.0 OR MIT. Cryptographic review and
spec-level feedback is welcome via
<https://github.com/Luminous-Dynamics/xenia-wire/issues>.*
