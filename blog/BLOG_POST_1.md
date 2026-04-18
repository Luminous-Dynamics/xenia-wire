# Announcing Xenia — a PQC-sealed remote-control protocol you can actually audit

**Target**: Hacker News (Show HN variant), lobste.rs, r/rust.
**Status**: draft, not yet posted. Adjust the tone per venue.
**Length**: ~1,100 words; roughly 5-minute read.
**Pre-alpha banner is load-bearing** — please do not soft-pedal it
when posting.

---

## The short version

I've just published [`xenia-wire`](https://crates.io/crates/xenia-wire) —
a pre-alpha Rust crate for a new remote-control wire protocol called
**Xenia**. It seals application payloads (screen frames, input events,
control messages) with ChaCha20-Poly1305 AEAD, protects against replay
with a sliding 64-slot window, rotates keys without dropping in-flight
envelopes, and ships a specification that's detailed enough for an
independent implementer in another language. The whole thing is
Apache-2.0/MIT dual-licensed, designed from day one to accept a
post-quantum handshake (ML-KEM-768), and has a consent-ceremony
primitive for authorizing sessions.

**It is pre-alpha.** The wire format is not yet frozen. The handshake
layer is a placeholder. No formal cryptographic review has happened.
Do not put this in production. I'm publishing now specifically to
invite review before the format stabilizes.

```
crate:  https://crates.io/crates/xenia-wire/0.1.0-alpha.3
repo:   https://github.com/Luminous-Dynamics/xenia-wire
spec:   https://github.com/Luminous-Dynamics/xenia-wire/blob/main/SPEC.md
paper:  https://github.com/Luminous-Dynamics/xenia-wire/blob/main/papers/xenia-paper.md
```

---

## Why this protocol exists

Commercial remote-control tools — ConnectWise ScreenConnect,
TeamViewer, AnyDesk, Splashtop — concentrate three things in one
vendor: identity, authority, and authentication. When any of those
three is compromised at the vendor layer, every downstream managed
service provider is compromised in parallel. The ConnectWise
CVE-2024-1709 breach of February 2024 is the canonical demonstration:
an authentication-bypass flaw was weaponized within 24 hours, and
ransomware affiliates used it to reach dozens of MSP client networks
through a single vendor hole.

Patching the specific CVE doesn't alter the topology. The topology is
the problem.

Xenia doesn't solve the full trust-topology problem in 0.1. It does
one smaller thing cleanly: it specifies a wire protocol that cleanly
separates *wire security* (symmetric crypto on the byte level) from
*trust topology* (whose identity vouches for whom). The wire is an
open, byte-deterministic specification that any language can
implement. The trust topology is a separate companion line of work
building on Holochain — the authors' organization has that research
underway, and Xenia's architecture is designed so the two can compose
without changing the wire format.

---

## What's in the box today

- **ChaCha20-Poly1305 AEAD** with a 12-byte nonce structured as
  `source_id[0..6] | payload_type | epoch | sequence[0..4]`.
- **64-slot sliding replay window** keyed by `(source_id,
  payload_type)`, matching IPsec/DTLS semantics.
- **Previous-key grace period** so in-flight envelopes still open
  after rekey. Five seconds by default, configurable.
- **Optional LZ4-before-AEAD compression** (measured 2.12× on live
  Pixel 8 Pro capture — the factor only exists *before* the AEAD,
  because ciphertext is pseudorandom).
- **Generic `Sealable` trait** — bring your own payload type, or use
  the reference `Frame` / `Input` types.
- **Zeroize-on-drop** key material.
- **Consent ceremony** (SPEC draft-02 §12) — Ed25519-signed
  `ConsentRequest` / `ConsentResponse` / `ConsentRevocation` payloads
  with a session-level state machine; `FRAME` traffic is gated on
  approved state.
- **A browser demo** (`xenia-viewer-web`) that runs the full seal/open
  roundtrip in WebAssembly. Build with `wasm-pack`, serve the output
  statically.
- **87 tests** across 8 suites (unit, integration, property, smoke
  fuzz, test-vector regression), plus a `cargo-fuzz` scaffold for
  deeper campaigns.
- **6 + 3 deterministic hex test vectors** so cross-language
  implementers can validate byte-for-byte compatibility without
  reading the Rust source.

## What I deliberately did NOT build

- A transport. Xenia is transport-agnostic — TCP, WebSocket, QUIC,
  UDP, offline file transfer all work.
- A handshake. Session keys arrive from an outer layer. The ML-KEM-768
  + Ed25519 handshake is a separate specification (Track 2.5, coming).
- A TLS replacement. Use TLS where TLS fits.
- A full MSP workflow. Ticketing, billing, tenant management — those
  live above the wire.

## What I genuinely don't know yet

- Whether the nonce layout survives a thorough symbolic-cryptography
  review.
- Whether my consent-signature-over-bincode-v1 binding is the right
  trust surface, or whether the AEAD session key should bind into the
  signature too.
- Whether the "Pending state allows FRAME" default (making consent
  enforcement opt-in once started) is the right compatibility trade —
  alternative is consent-required-from-session-start.
- Whether any of the tests I wrote exercise the failure modes that
  actually matter. (The smoke fuzzer has run ~310,000 random
  envelopes without panic — that's a floor, not a ceiling.)

I'm publishing early to find out.

---

## What I'd love from you

If you're a cryptographer and you've got 15 focused minutes: the
specific thing I want reviewed is **SPEC.md §3 (nonce construction)
and §5 (replay window)**. I'm not claiming a novel primitive — I'm
claiming a specific *composition* of ChaCha20-Poly1305, IPsec-style
replay protection, and a nonce layout that supports multi-stream
operation under one session key. If the composition has a hole, I'd
rather find it now than in v0.2.

If you build or operate MSP infrastructure: the specific thing I want
is a reality-check on the *threat model* in §6.2 of the paper. Does
the decentralized-trust architecture map to how you actually think
about risk, or am I pattern-matching from the wrong direction?

If you're writing a client in a different language: the test vectors
in `test-vectors/` are byte-for-byte reproducible against fixed
fixture parameters. If your implementation diverges from them, either
your implementation is wrong or my spec is wrong — both useful
findings. I want to hear either.

[Open a GitHub issue](https://github.com/Luminous-Dynamics/xenia-wire/issues)
for design feedback. For security-sensitive reports please use
[private advisories](https://github.com/Luminous-Dynamics/xenia-wire/security/advisories/new)
rather than public issues.

---

## What happens next

No firm dates. Roughly:

1. Soliciting informal cryptographer review for 2–4 weeks.
2. Publishing an academic paper draft with the empirical evaluation
   (bandwidth measurements, head-of-line-blocking comparisons under
   packet loss, LZ4-before-AEAD compression ratios — all on real
   Pixel 8 Pro hardware, all reproducible). The draft is already in
   the repo; venue decision is pending.
3. If and when the wire format stabilizes: v0.1.0 stable, then
   Track 2.5 (ML-KEM handshake), then higher-layer integrations.

I am intentionally not making this a product pitch. The crate will
stay open-source and permissively licensed. Commercial-license
discussions, if they happen, are gated on signals that aren't in yet.

## Credits

Xenia sits on the shoulders of
[RustCrypto's `chacha20poly1305`](https://github.com/RustCrypto/AEADs),
Yann Collet's [LZ4](https://github.com/lz4/lz4), Trevor Perrin's
[Noise Protocol Framework](http://www.noiseprotocol.org/noise.html),
and the cumulative IETF work on sliding-window replay protection
(RFC 4303, RFC 9147). The specification's structure owes a debt to
the Noise and DTLS drafts specifically.

The name *Xenia* is the ancient Greek covenant between guest and
host — the moral logic of remote access codified cryptographically.
A technician is a guest in a client's machine; the client extends
bounded hospitality; the protocol is the terms of that hospitality.
The etymology is in the paper.

*Pre-alpha. Review welcome. — Tristan*
