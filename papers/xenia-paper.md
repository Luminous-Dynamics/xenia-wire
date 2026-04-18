# Xenia: A Post-Quantum-Ready, Decentralized-Trust Wire Protocol for Remote Control

**Tristan Stoltz**\*  
*Luminous Dynamics*  
`tristan.stoltz@evolvingresonantcocreationism.com`

**Draft**, 2026-04-18. Corresponds to `xenia-wire 0.1.0-alpha.1` + SPEC draft-01.

\* Sole author. This draft solicits co-author participation from
cryptographers and MSP security practitioners — see §8 for how to
engage.

---

## Abstract

Commercial remote-control protocols (ConnectWise ScreenConnect,
TeamViewer, AnyDesk) concentrate trust in a vendor-operated relay
and authenticate their technicians through a vendor-issued identity.
The ConnectWise ScreenConnect authentication-bypass vulnerability of
February 2024 (CVE-2024-1709) — an unauthenticated remote code
execution flaw that affected every on-premise installation — demonstrated
that this architecture's single point of failure is not hypothetical.
When the vendor's identity system breaks, every downstream managed
service provider breaks with it.

We present *Xenia*, a binary wire protocol for remote-control streams
that (i) uses ChaCha20-Poly1305 AEAD with a nonce layout designed for
replay-protected multi-stream operation under a single session key,
(ii) separates the identity/consent layer from the transport-crypto
layer so each can be audited independently, (iii) is transport-agnostic
(TCP, WebSocket, QUIC, UDP all acceptable), (iv) compresses before
sealing where compression is useful, and (v) is designed from day
one to receive a post-quantum key-encapsulation handshake (ML-KEM-768)
once the handshake is specified. Xenia is published as an open
specification (SPEC.md draft-01) and reference implementation
(`xenia-wire`) on crates.io under Apache-2.0/MIT.

Empirical measurements on real mobile hardware — Google Pixel 8 Pro,
USB 2.0 tether to a NixOS workstation — show a 3.27–3.52× bandwidth
reduction from bincode+AEAD vs. JSON+AEAD baseline, an additional
2.12× reduction from LZ4-before-AEAD compression, and a 4.7×
head-of-line blocking advantage for QUIC over WebSocket at 1% packet
loss. We describe the design rationale, the empirical methodology, and
the design-space in which Xenia differs from the existing commercial
and open-source alternatives. The protocol and paper are pre-alpha
and solicit cryptographic review.

**Keywords**: remote control, authenticated encryption, replay
protection, post-quantum cryptography, decentralized trust, remote
access, managed service providers, LZ4.

---

## 1. Introduction

### 1.1 A single point of failure, annualized

In February 2024, an authentication-bypass vulnerability
(CVE-2024-1709) in ConnectWise ScreenConnect allowed unauthenticated
remote code execution against any reachable instance. ScreenConnect
is the remote-control backbone of thousands of managed service
providers (MSPs); the vulnerability was weaponized within 24 hours
of disclosure; ransomware affiliate groups, including Black Basta,
exploited the flaw to deploy payloads across dozens of MSP customers
simultaneously [@connectwise2024]. The breach pattern was
characteristic: compromise the MSP tool, inherit the MSP's
authenticated access to N client networks, deploy ransomware at
scale.

The architectural root cause is not a specific coding error. It is
that modern MSP tools concentrate three things in one vendor:

1. Identity (who the technician is);
2. Authority (whose machines they can reach);
3. Authentication (how they prove it).

When any of these three is compromised at the vendor layer, every
downstream MSP relationship is compromised in parallel. No amount
of patching the specific CVE alters this topology.

### 1.2 Two orthogonal problems

A remote-control system needs to solve two problems that are often
conflated:

- **Wire security**: how does a technician's client send screen-view
  bytes and input events to a customer's machine without an on-path
  attacker tampering, replaying, or reading them? This is a symmetric
  cryptography problem.
- **Trust topology**: whose identity vouches for the technician? Whose
  agent key signed the authority that lets them connect? What happens
  when an attacker gets that signing key?

Modern commercial tools answer both questions with "the vendor."
ConnectWise ScreenConnect answers them with ScreenConnect's server.
TeamViewer answers them with TeamViewer's account system. The wire
layer is AES-256 or similar, and is typically sound in isolation;
the trust topology is a ~3-company oligopoly.

Xenia addresses only the first problem at 0.1 — the wire — but does
so in a way that leaves the trust topology open to being answered
by a decentralized identity system rather than a vendor. The present
paper documents the wire; a companion line of work in the authors'
organization is building the decentralized trust layer on Holochain.

### 1.3 Contributions

1. A precisely-specified binary wire format (§3, §4 and SPEC.md)
   with a nonce layout designed for multi-stream operation under a
   single session key, an IPsec/DTLS-style 64-slot sliding replay
   window per `(source_id, payload_type)` stream, and a
   previous-key grace period for lossless rekey.
2. Empirical measurements on real mobile hardware characterizing
   bandwidth (§5.1), head-of-line-blocking tails under packet loss
   (§5.2), and the compression-before-AEAD effect (§5.3). All
   measurements reproducible from the published `xenia-wire` crate
   and the accompanying measurement harnesses.
3. An explicit design posture that separates the wire layer (this
   paper) from the handshake (a forthcoming ML-KEM-768 specification,
   Track 2.5 in the authors' roadmap) and from the consent ceremony
   (a forthcoming Xenia draft-02 addition, Week-5 of the Track A plan).
   The separation is intentional: a remote-control protocol that
   tries to specify all three at once has historically produced
   monolithic, unaudited, vendor-locked systems.
4. An open specification (`SPEC.md` draft-01) written to the standard
   that an independent implementer in a different language can build
   an interoperable client without reading the Rust source. Reference
   test vectors ship with every byte reproducible.

### 1.4 Non-contributions

This paper does not propose a novel cryptographic primitive. ChaCha20,
Poly1305, LZ4, and sliding-window replay protection are all
well-understood building blocks with decades of analysis. The
contribution is in how they compose and in the trust-topology
context that composition enables — not in the primitives themselves.

This paper does not specify the handshake. Session keys in
`xenia-wire 0.1.x` arrive from an outer layer; the ML-KEM-768
handshake is deferred to a companion draft. This is deliberate —
an AEAD wire and a post-quantum key exchange are two hard problems
that benefit from independent review.

This paper does not compare to TLS 1.3. Xenia is not a TLS
replacement; it targets a different deployment model. Where TLS
fits, TLS should be used.

---

## 2. Related work

### 2.1 Remote-desktop protocols

Microsoft RDP [@microsoft_rdp], VNC/RFB [@vnc1998], and Apache
Guacamole [@guacamole] define screen-sharing semantics: pixel
encoding, input-event taxonomy, session control. They do not fix a
transport security model — RDP optionally wraps in CredSSP/TLS,
VNC historically ran in cleartext, Guacamole relays into an
HTTPS-fronted container. Xenia does not compete with these at the
semantics layer; an application built atop Xenia could carry
RDP-like or VNC-like payloads in its application frames.

### 2.2 Commercial MSP tools

ConnectWise ScreenConnect, TeamViewer, AnyDesk, and Splashtop are
the dominant commercial remote-control tools in the MSP industry.
Their wire protocols are proprietary; their architecture is broadly
understood from documentation, network captures, and — in
ConnectWise's case — from the public postmortem of CVE-2024-1709.
All four share the centralized-trust topology described in §1.2.

### 2.3 Open-source alternatives

RustDesk [@rustdesk] is a modern open-source remote-desktop tool
that demonstrates the technical feasibility of a user-controlled
rendezvous server. It is AGPL-3.0 licensed, which creates
adoption friction for MSPs that need to embed the protocol in
commercial products. Xenia's licensing (Apache-2.0/MIT) is an
explicit design choice to make adoption friction low where RustDesk
makes it deliberately high.

MeshCentral [@meshcentral] and Tactical RMM [@tactical] target
MSPs directly. They use open protocols but concentrate identity
in a self-hosted server — a better position than a vendor-hosted
one, but still architecturally centralized per-deployment.

### 2.4 Modern AEAD + replay protocols

The Noise Protocol Framework [@noise] and Signal's Double Ratchet
[@signal] are the canonical modern references for symmetric
cryptographic protocols with forward secrecy and replay protection.
Xenia's wire differs in several design decisions:

- Xenia does not include a KDF/ratchet — session keys arrive from
  an outer layer and rotate via full rekey, not per-message.
- Xenia's replay window is keyed by `(source_id, payload_type)`
  to allow multiple concurrent streams under one session key.
- Xenia's nonce layout intentionally parallels the `packet_crypto`
  primitives in the Symthaea mesh layer [@symthaea_mesh], to allow
  future interop with that research stack.

### 2.5 QUIC and modern transports

QUIC [@rfc9000] is the transport of choice for low-latency streaming
applications because of its head-of-line-blocking isolation at the
stream level. Xenia is transport-agnostic, but §5.2 documents that
the choice of transport materially affects the tail latency of
Xenia-sealed traffic under packet loss.

### 2.6 Post-quantum key exchange

NIST's PQC standardization process produced ML-KEM-768 (formerly
Kyber-768) [@fips203] as a lattice-based key-encapsulation
mechanism resistant to Shor's algorithm. Session keys established
today over a non-PQ handshake are exposed to future "harvest now,
decrypt later" attacks. For MSP traffic — which routinely carries
credentials, financial records, and medical information — the
5-to-15-year sensitivity window exceeds the timeline on which
practical quantum attacks on RSA/ECDH may emerge. Xenia does not
specify a handshake in 0.1.x, but is designed so an ML-KEM-768
handshake can drop in without wire-format change.

---

## 3. The Xenia wire

### 3.1 Envelope layout

Every sealed Xenia message is a single byte string — an *envelope*
— of at least 28 bytes:

```
┌──────────┬─────────────┬─────────┐
│  nonce   │  ciphertext │   tag   │
│  12 B    │  variable   │  16 B   │
└──────────┴─────────────┴─────────┘
```

Ciphertext and tag are produced by ChaCha20-Poly1305 over the
application plaintext. No outer length prefix is included; the
transport is responsible for delimiting envelopes (WebSocket
binary-frame boundary, QUIC stream boundary, TCP length prefix,
filesystem file — all acceptable).

### 3.2 Nonce construction

The 12-byte nonce is the security-critical field:

```
byte:  0                5 6          7 8            11
       ┌────────────────┬─┬────────────┬─────────────┐
       │   source_id    │p│   epoch    │   sequence  │
       │    (6 bytes)   │t│   (1 byte) │   (4 LE u32)│
       └────────────────┴─┴────────────┴─────────────┘
                          ↑
                     payload_type (1 byte)
```

- `source_id` (bytes 0..6): 48 bits of per-session randomness, stable
  for the session's lifetime (including across rekeys).
- `payload_type` (byte 6): stream identifier; domain-separates
  concurrent streams under one key.
- `epoch` (byte 7): per-session random byte. Additional defense against
  accidental `source_id` collision.
- `sequence` (bytes 8..12): little-endian unsigned 32-bit counter,
  monotonic per stream on the sender, reset to 0 on rekey.

### 3.3 Rationale for this layout

The three decisions worth unpacking:

**Why 48 bits of `source_id` rather than 64 or 96?** The IETF nonce
pattern in RFC 8439 uses 32 bits of counter + 64 bits of random.
We deviate because the replay window must be keyed by stable
per-stream bytes, which means those bytes must be part of the
wire format, not randomized. 48 bits is the birthday-collision
boundary at roughly 2^24 concurrent sessions — well above any
realistic single-deployment scale.

**Why is `payload_type` in the nonce rather than in a header?**
Making it part of the nonce is free (it was reserved in the
`packet_crypto` layout from which this descends) and eliminates
the possibility of an attacker confusing the decoder by
swapping the payload-type byte elsewhere in the message. If an
attacker flips the `payload_type` byte, the AEAD tag fails because
the nonce changed.

**Why a 32-bit sequence rather than 64-bit?** To preserve the
IPsec-style 64-slot replay window semantics while keeping the wire
overhead moderate. The sender-side counter is 64-bit internally;
the receiver operates on the low 32 bits. Sequence-wraparound is
a cryptographic cliff — the reference implementation enforces a
`SequenceExhausted` error at 2^32 seals to prevent silent nonce
reuse (§SPEC.md §3.1).

### 3.4 Replay window

The receiver maintains, per `(source_id, payload_type)` tuple, a
64-bit sliding window bitmap. An incoming envelope with sequence
`seq` is accepted iff (i) `seq > highest_seen` (strictly new; shift
and set bit 0), or (ii) `highest_seen - seq < 64` and the
corresponding bit is unset (out-of-order but in-window; set the
bit). Too-old and duplicate sequences are rejected. The design
mirrors RFC 4303 ESP [@rfc4303] and DTLS 1.3 [@rfc9147].

### 3.5 LZ4 before AEAD

When compression is beneficial, Xenia applies LZ4 *before* the
AEAD seal. The reason is elementary but frequently gotten wrong:
ChaCha20-Poly1305 ciphertext is pseudorandom and does not compress.
An external compressor applied after the seal wastes CPU for zero
byte reduction. Applied before the seal — to the bincode-encoded
plaintext — LZ4 produces the reduction documented in §5.3.

A distinct `payload_type` (`0x12` `FRAME_LZ4` vs. `0x10` `FRAME`)
signals to the receiver that decompression is required. The two
payload types carry independent replay windows, allowing a sender
to interleave raw and compressed frames on one session key.

### 3.6 Key lifecycle

`Session::install_key(key)` installs a 32-byte ChaCha20-Poly1305
key. Subsequent `install_key` calls perform a rekey: the existing
key is moved to `prev_key` with a grace-period expiry (5 seconds
by default); the new key becomes current; the nonce counter resets
to 0. The grace period allows in-flight envelopes sealed under the
old key to continue opening successfully — a property that matters
at 30 frames/second, where a naïve "drop all old envelopes at
rekey" policy would lose ~150 frames per rotation.

The replay window is NOT cleared on rekey. `source_id` is stable
for the session's lifetime, so the `(source_id, payload_type)`
stream persists across rekey, preventing a cross-rekey replay
from an attacker who captured old envelopes.

---

## 4. Architecture

### 4.1 Component separation

The Xenia stack is deliberately layered so each layer can be
audited and replaced independently:

```
┌──────────────────────────────────────────────────────┐
│  application (screen frames, input events, control)  │
├──────────────────────────────────────────────────────┤
│  consent ceremony (SPEC draft-02, not in 0.1.x)       │
├──────────────────────────────────────────────────────┤
│  attestation log (SPEC draft-02, not in 0.1.x)        │
├──────────────────────────────────────────────────────┤
│  xenia-wire (this paper, this SPEC)                   │
├──────────────────────────────────────────────────────┤
│  handshake — ML-KEM-768 + Ed25519 (Track 2.5)         │
├──────────────────────────────────────────────────────┤
│  transport (TCP / WebSocket / QUIC / UDP)             │
└──────────────────────────────────────────────────────┘
```

Each layer has a defined interface to the layers above and below.
The wire takes keys as input and produces sealed bytes as output.
It does not care where the keys came from (handshake) or how the
bytes reach the peer (transport). The consent ceremony and
attestation log sit above the wire because they concern who is
allowed to send *what* — an application-level question — not how
the bytes are protected.

### 4.2 What is in 0.1.x

- `xenia-wire` crate on crates.io (`0.1.0-alpha.1`, Apache-2.0/MIT).
- SPEC.md draft-01 (§3 of this paper is a summary; the
  specification is the normative reference).
- 6 deterministic test vectors for cross-implementation validation.
- 65 tests covering unit, integration, property (proptest ~2,560
  effective runs), smoke-fuzz (~310k random envelopes), and
  test-vector regression.
- `cargo-fuzz` scaffold for deeper coverage-guided campaigns.

### 4.3 What is deferred

- The handshake (Track 2.5). In 0.1.x callers install a 32-byte
  key directly.
- The consent ceremony and attestation log (SPEC draft-02, Week-5
  of the authors' Track A plan). Reserved payload-type range
  `0x20..0x2F` is held for these.
- A WASM browser viewer (Track A Week 4) — the reference
  implementation is native Rust; a browser-resident verifier is
  separately published.

---

## 5. Empirical evaluation

### 5.1 Methodology

All measurements in this section were taken on the same hardware
configuration to enable cross-measurement comparison:

- **Phone**: Google Pixel 8 Pro (Tensor G3, 1440×3120, 120Hz display),
  Android 14. The device is the sender in the forward path and the
  receiver in the reverse path. Screen capture via `scrcpy` v2.4
  with Tensor G3 HEVC hardware encoder.
- **Workstation**: NixOS 26.05 (kernel 6.19.10), 16-core x86_64,
  32 GB RAM. Peer endpoint of the wire.
- **Link**: USB 2.0 tether between phone and workstation, also
  carrying the workstation's internet traffic. Effective throughput
  ~40 MB/s in each direction.
- **Crate version**: `xenia-wire 0.1.0-alpha.1`. All empirical runs
  are reproducible from the published crate; measurement harnesses
  are in `examples/` and `symthaea/scripts/phase_*`.

All numbers are single-device measurements. They establish a
point estimate suitable for design-decision arbitration — not
population-level statistical claims. We do not claim these
numbers generalize to fleet deployments; we claim they are
reproducible on this hardware.

### 5.2 Bandwidth: bincode + AEAD vs. JSON + AEAD

On captured frame payloads from a live scrcpy session (delta
frames dominated by sparse patch updates), bincode+AEAD produces
a **3.27× to 3.52× reduction** in envelope size compared to JSON
+AEAD. The reduction concentrates in delta-frame payloads, where
dense i8-quantized patch arrays encode at ~1 byte per value in
bincode but ~4 ASCII bytes per value in JSON.

This measurement establishes the baseline case for adopting the
binary wire: even without LZ4 and without the PQC angle, the
binary envelope is a 3×+ win over a naïve JSON transport. For MSP
deployments where bandwidth is constrained (cellular, satellite,
bandwidth-metered links), this is material — a 1-hour session
moves from ~150 MB to ~45 MB.

### 5.3 LZ4-before-AEAD

On the same captured frames, LZ4-before-AEAD produces a further
**2.12× reduction overall** and **2.20× on steady-state delta
frames**. Combined with §5.2, a deployment that uses LZ4 and
bincode sends ~6.9× fewer bytes than a naïve JSON deployment.

At 30 fps with a realistic frame-size distribution (mix of full
and delta frames), the raw-seal path totals 18.35 MB/s; the
LZ4+seal path totals 8.34 MB/s. The 8.34 MB/s figure is relevant
because it is the network-friendly ceiling for sustained USB 2.0
tethering or mid-tier cellular — the raw path exceeds that
budget; the LZ4 path clears it with ~5% margin.

We reiterate the correctness property: LZ4 **must** precede AEAD.
Ciphertext is pseudorandom; compression after the seal is always
zero-yield CPU waste. This is a well-known result in cryptographic
engineering but we note it because it is also a routinely-violated
one.

### 5.4 Head-of-line blocking: WebSocket vs QUIC

WebSocket over TCP shares a single congestion window across all
streams, which means a single lost packet stalls *all* frame
deliveries until retransmission. QUIC isolates congestion per
stream, which means a lost packet on stream A does not delay
stream B.

We measured this effect by running identical Xenia-sealed frame
streams over WebSocket and over QUIC, injecting packet loss
with the Linux `tc qdisc netem` module (unprivileged user
namespaces; no `sudo` required). At **1% injected loss**, WebSocket
tail latency (p99.9) inflates **4.7×** relative to the lossless
baseline; QUIC stays within **2×** of lossless. At **5% loss**,
WebSocket tail inflates **5.3×**; QUIC stays within **2×**.

This is the single most important transport-choice result in
this paper: Xenia's wire is transport-agnostic, but a deployer
who chooses WebSocket accepts the head-of-line tail regardless
of how efficient the wire is. The empirical recommendation for
loss-prone links (cellular, Wi-Fi, satellite) is QUIC; for
low-loss wired links (Ethernet, USB tether, datacenter), WebSocket
is fine and operationally simpler.

### 5.5 Mobile encoding throughput

We characterized the sustainable HEVC encoding throughput on
the Tensor G3 via `scrcpy` v2.4 in single-CPU software-decode
mode on the workstation side. The canonical 30-second sustain
run delivers **16 fps mean / 23 fps peak** at 1440×3120 with
HEVC Main profile. With GPU-accelerated decode the ceiling
rises toward 30 fps at the same resolution.

The 16/23 fps numbers are not Xenia's wire limit — they are
the upstream encoder limit. Xenia's wire handles whatever
the transport delivers; the implication is operational:
sustaining 30 fps on a mobile-first deployment requires GPU
decode (trivially available on modern workstation-class
hardware; unavailable on, e.g., a Raspberry Pi relay).

### 5.6 Wraparound cliff — observed and fixed

During self-review before external circulation, we observed that
the reference implementation's `seal` function silently wrapped
the 32-bit nonce sequence at 2^32 envelopes, which under
ChaCha20-Poly1305 would catastrophically break confidentiality
on the very next seal. We added `WireError::SequenceExhausted`
that surfaces the boundary as an actionable error (commit
`1146853`). The fix is one conditional; the lesson — that a
documented invariant unenforced at the API boundary is a latent
fault — is the interesting one.

The reader may reasonably ask whether other latent invariants
exist. We list the ones we know about in SPEC.md §10.6 ("Known
non-properties"). We actively solicit cryptographic review for
the ones we don't (§8).

---

## 6. Discussion

### 6.1 Design-space comparison

| Dimension | ConnectWise | TeamViewer | AnyDesk | RustDesk | **Xenia** |
|-----------|-------------|------------|---------|----------|-----------|
| Wire spec public? | No | No | No | Partial | Yes (SPEC.md) |
| PQC-ready? | No | No | No | No | Yes (Track 2.5) |
| Trust topology | Vendor | Vendor | Vendor | Self-host | Decentralizable |
| Mobile-first? | Patched-on | Yes | Yes | Patched-on | Measured on Pixel 8 |
| Compression-under-loss? | — | — | — | — | LZ4-before-seal |
| License | Proprietary | Proprietary | Proprietary | AGPL-3.0 | Apache/MIT |
| Test vectors? | No | No | No | No | 6, deterministic |

The Xenia column is aspirational on the post-quantum and
decentralized-trust axes — draft-01 specifies the wire; the
handshake and consent-ceremony work is explicitly deferred. But
the aspiration is encoded in the *structure* of the specification
(reserved payload types, layered architecture) so that executing on
the remaining axes does not require a breaking change to deployed
0.1.x code.

### 6.2 Where Xenia should not be used

Three deployment profiles where Xenia is the wrong tool:

1. **Where TLS suffices.** If the application fits TLS 1.3 cleanly
   (web/browser, mutual-TLS enterprise), use TLS. Xenia is not an
   improvement on TLS for TLS's deployment envelope; it is a
   different tool for a different deployment envelope.
2. **Where centralized trust is acceptable and simple.** A vendor
   with strong identity posture and audit access (a SOC 2-certified
   MSP tool with clear incident-disclosure history) may be a rational
   choice for organizations that cannot staff cryptographic review
   internally. Xenia's decentralized-trust story shifts work onto
   the deployer.
3. **Where the wire is not the bottleneck.** If the threat model
   is compromised-endpoint (a malicious technician, a phished
   customer), no wire protocol saves you. Xenia composes with
   endpoint security controls; it does not replace them.

### 6.3 The layered-review strategy

We deliberately split the protocol into four concerns (transport,
wire, handshake, consent) so that each layer can be reviewed by
specialists who don't need to understand the others. A
cryptographer reviewing the wire (SPEC.md) does not need to read
the consent-ceremony spec. A cryptographer reviewing the ML-KEM
handshake (Track 2.5) does not need to read the replay-window
semantics. This is standard cryptographic-engineering hygiene —
monolithic protocols are famously hard to audit, and Xenia trades
a modest amount of interface-friction for a much cleaner audit
surface.

---

## 7. Future work

### 7.1 Post-quantum handshake (Track 2.5)

The ML-KEM-768 + Ed25519 handshake specification will deliver:

- **Identity**: Ed25519 long-term signing keys on both peers, with
  application-defined trust anchors.
- **Key encapsulation**: ML-KEM-768 producing a 32-byte shared
  secret.
- **Session key derivation**: HKDF-SHA-256 with a protocol-specific
  salt and info label.
- **Rekey**: asynchronous re-handshake on a timer or on explicit
  request; the already-specified Xenia grace period handles the
  transition without frame loss.

Target: a separate companion specification, reviewed separately,
published before the consent-ceremony addition.

### 7.2 Consent ceremony (Week-5 of the Track A plan)

Three wire-level additions reserved in the payload-type registry:

- `0x20` `ConsentRequest` — technician asks end-user to approve the
  session, with a scope (screen / keyboard / files / shell) and a
  time limit. Signed by technician's device key.
- `0x21` `ConsentResponse` — end-user approves or denies, signed
  by their device key.
- `0x22` `ConsentRevocation` — end-user terminates the session
  mid-stream, asymmetrically. Subsequent frames from the technician
  return `WireError::ConsentRevoked`.

A `causal_binding: Option<CausalPredicate>` field on `ConsentRequest`
is reserved for a forthcoming v1.1 Ricardian-contract extension
("authority valid while ticket #1234 is In-Progress") — the authors
see this as the most distinctive single contribution of the full
program. It composes naturally with the Holochain-based
decentralized-trust layer under development in the authors'
organization.

### 7.3 Attestation-chained action log (Week-5)

Every command a technician issues is signed by their device key
and recorded with a monotonic sequence and a hash of the prior
entry — a blockchain-of-one-technician. An auditor can verify the
chain retroactively to prove no tampering.

### 7.4 Consciousness-gated session oversight (speculative)

The authors' parent project, Symthaea, is a consciousness-first
cognitive architecture with a formalized moral algebra (16 duties,
restorative justice framework, 92.9% ETHICS-benchmark). A future
paper will explore whether Symthaea's side-car can observe the
outbound frame stream and dispatch consciousness-gated responses
("this stream contains what appears to be a password-entry field
— suggest the technician request elevated consent"). This is
research, not engineering — we flag it as speculative and as
future work rather than as a claim.

### 7.5 WAN split-cognition experiments (further future)

Once the handshake and consent ceremony are specified, the
authors' Phase IV research work investigates whether
geographically-distributed cognitive processes (split Markov
blankets) can maintain coherent behavior across the Xenia
transport under realistic WAN conditions. The present paper's
QUIC-vs-WebSocket measurements are one early input to that line
of research.

---

## 8. Conclusion and call for review

Xenia is a precisely-specified, empirically-characterized wire
protocol that takes the well-understood composition of
ChaCha20-Poly1305 + sliding-window replay protection + LZ4
compression and places it within an architecture designed to
accept a post-quantum handshake and a decentralized-trust
identity layer without wire-format change. The 0.1-alpha release
is pre-alpha; the purpose of publication at this stage is to
invite review before the wire format stabilizes.

Specifically, we invite:

- **Cryptographers** — on the nonce layout (§3.2), the
  replay-window semantics (§3.4), the key lifecycle (§3.6), and
  the known-non-properties list (SPEC.md §10.6). Bounded
  question: "Do you see a latent failure mode we haven't
  enumerated?" Contact via
  <https://github.com/Luminous-Dynamics/xenia-wire/security/advisories/new>.
- **MSP practitioners** — on the architecture (§4) and the
  deployment-profile discussion (§6.2). Bounded question: "Does
  this architecture match the threat model you operate under?"
  Contact via GitHub issues.
- **Systems engineers** — on the transport measurements (§5) and
  the QUIC-vs-WebSocket recommendation (§5.4). Bounded question:
  "Have you measured similar effects on other hardware / links?
  Do you have counter-examples?"

The specification, reference implementation, empirical harnesses,
and test vectors are all published under Apache-2.0 or MIT. The
test vectors are byte-deterministic — an implementation in a
different language can be validated against the fixtures without
consulting the Rust source.

---

## Acknowledgments

This work builds on the `RustCrypto` project [@rustcrypto] — in
particular the `chacha20poly1305` crate — and on Yann Collet's
LZ4 compression work [@lz4]. The QUIC measurements used the
Linux `netem` traffic control module. The mobile encoding
measurements used `scrcpy` v2.4 by Genymobile [@scrcpy]. The
specification draft owes its structure to comparable IETF
documents, particularly RFC 4303 (IPsec ESP) and RFC 9147
(DTLS 1.3).

Pre-alpha review invited — see §8.

---

## Appendix A. Reproducibility checklist

| Item | Status | Path |
|------|--------|------|
| Reference implementation | Published | `crates.io/crates/xenia-wire/0.1.0-alpha.1` |
| Full specification | Published | `SPEC.md` draft-01 |
| Deterministic test vectors | Published | `test-vectors/` |
| Property tests | Runs in CI | `tests/proptest_wire.rs` |
| Smoke fuzzer | Runs in CI | `tests/smoke_fuzz.rs` |
| Coverage-guided fuzzer | Scaffolded | `fuzz/` |
| Bandwidth measurement harness | External | `symthaea/scripts/phase_1a_*` |
| HoL measurement harness | External | `symthaea/scripts/phase_1c_netem_ab.sh` |
| LZ4 measurement harness | External | `symthaea/examples/phase_2a_lz4_measurement.rs` |

All external harnesses cited are in the authors' research
monorepo and are expected to be open-sourced alongside a
companion measurement paper.

---

## Appendix B. Change history

| Version | Date | Changes |
|---------|------|---------|
| Draft (this document) | 2026-04-18 | Initial pre-alpha draft. |

---

## References

Bibliography is in `papers/refs.bib`.

Citations used in this draft:
`connectwise2024`, `microsoft_rdp`, `vnc1998`, `guacamole`,
`rustdesk`, `meshcentral`, `tactical`, `noise`, `signal`,
`symthaea_mesh`, `rfc9000`, `fips203`, `rfc4303`, `rfc9147`,
`rustcrypto`, `lz4`, `scrcpy`.
