# Xenia Wire Protocol — Specification draft-01

> **Status**: draft-01. Corresponds to `xenia-wire 0.1.0-alpha.1`
> (published 2026-04-18). Pre-alpha — the format is subject to
> breaking change in subsequent drafts. Reviewers: please open an
> issue for any ambiguity; the spec is the normative reference, not
> the Rust source.
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

This document specifies **draft-01** of the wire protocol. The spec
version is independent of the `xenia-wire` crate version; the mapping
from crate version to wire draft is recorded in `CHANGELOG.md`.

Breaking changes to any of the following bump the spec to `draft-02`:

- Envelope layout or field order.
- Nonce construction.
- AEAD algorithm.
- Replay-window semantics.
- Payload type registry assignments.

Adding new payload types in the reserved ranges (§4.2) is not a
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
              | source_id | | pld_type  | | epch | |  sequence  |
              +-----------+ +-----------+ +------+ +------------+
               6 bytes       1 byte        1 byte   4 bytes (LE u32)
```

- **`source_id`** (bytes 0..6): 6 bytes of a per-session random
  identifier. Generated once when the session is constructed and
  held stable for the session's lifetime (including across rekeys).
  The Rust reference uses 8 random bytes internally and discards the
  top two — an alternative implementation MAY store only 6 bytes.

- **`pld_type`** (byte 6): the payload type, which identifies the
  logical stream. See §4 for registry. A given
  `(source_id, pld_type)` tuple defines an independent replay
  window; see §5.

- **`epch`** (byte 7): a per-session random epoch byte. Generated
  once at session construction. Provides domain separation between
  sessions that — by accident or adversarial intent — share both
  a session key and a `source_id`.

- **`sequence`** (bytes 8..12): a 32-bit unsigned integer,
  **little-endian**, taken from the low 32 bits of a monotonic
  64-bit counter maintained by the sender. The counter starts at
  `0` when a key is installed and increments by 1 on each seal.
  It resets to `0` on rekey.

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
3. `sequence` is monotonic per `(source_id, pld_type)` stream on the
   sender side.
4. The 32-bit sequence does not wrap before rekey. Implementations
   MUST enforce this by refusing to seal once the sender's counter
   reaches `2^32` — the very next seal would wrap to `0` under the
   same key, causing catastrophic nonce reuse. The reference
   implementation returns a `SequenceExhausted` error from `seal()`
   at that boundary; see §9.
   At 30 frames per second the boundary is ~4.5 years; at 30 kHz it
   is ~40 hours. Real sessions rekey every ~30 minutes, so the
   boundary is only reachable by a caller that has disabled or
   failed to trigger rekey.

### 3.2 Worked example

From test vector 01 (`test-vectors/01_hello_frame.envelope.hex`):

```
source_id = "XENIATST" (bytes 0..6 of ASCII, = 58 45 4e 49 41 54)
pld_type  = 0x10  (FRAME)
epch      = 0x42
sequence  = 0     (first seal, encoded as 00 00 00 00)

nonce     = 58 45 4e 49 41 54 10 42 00 00 00 00
```

The full envelope opens with this nonce and the fixture key to
produce the bincode-encoded `Frame` shown in
`test-vectors/01_hello_frame.input.hex`.

---

## 4. Payload type registry

The `pld_type` byte in nonce position 6 identifies the logical
stream. Two envelopes with different payload types never collide
on the replay window, and — because the payload type is part of
the nonce — never collide on the AEAD nonce stream either.

### 4.1 Assigned values (draft-01)

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
| `0x20..=0x2F` | `xenia` extensions | Reserved for Week-5 differentiators: consent ceremony (`0x20`/`0x21`/`0x22`), attestation-chained action log (`0x23`). Not yet implemented in draft-01. |
| `0x30..=0xFF` | applications | Free for caller-defined payload types. No IANA-style coordination — pick one and document it locally. |

### 4.3 Discarding unknown payload types

A receiver that opens an envelope with a `pld_type` it does not
recognize SHOULD treat the plaintext as opaque bytes and either
dispatch to a catch-all handler or drop the envelope. It MUST NOT
panic or terminate the session. Forward-compatibility in the
`0x13..=0x2F` range is intentional: a sender on a newer draft can
mix new payload types into a stream that a `draft-01` receiver
participates in.

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

On rekey (see §6), the replay window is NOT cleared. `source_id`
is stable for the session's lifetime, so the `(source_id,
pld_type)` stream persists across rekey. This prevents a cross-
rekey replay from an attacker who recorded old envelopes and
hopes the receiver will accept them after key rotation.

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
tailor probe traffic. Production implementations MUST treat all
open failures as indistinguishable to the remote peer.

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
to fail verification. The attacker's forgery probability is
bounded by ~2^-100 per attempt.

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
- **MSP workflow** — consent ceremony, attestation log,
  session recording are reserved payload-type ranges (§4.2) to
  be specified in future drafts (Week-5 deliverables of the
  Track A plan).
- **General AEAD library** — the nonce layout is specific to
  replay-protected streams; don't use the envelope format for
  unrelated purposes.
- **Transport framing** — the envelope is a single byte string.
  Delimiting it on the wire (length prefix, WebSocket binary
  frame, QUIC stream boundary) is the transport's job.

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
| draft-01 | 2026-04-18 | `0.1.0-alpha.1` | Initial publication. |

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
