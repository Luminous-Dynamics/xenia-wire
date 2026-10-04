# Security Policy

`xenia-wire` is a cryptographic protocol implementation. We take
vulnerabilities seriously and appreciate responsible disclosure.

## Status

`0.2.0-alpha.x` is **pre-alpha**. The wire format, consent ceremony, and
optional handshake surfaces are still subject to change, and no independent
cryptographic review has occurred. Do not deploy in production.

A normative specification and test-vector suite exist, but they are not a
substitute for external review. If you find something worth knowing, we want to
know it now rather than after others depend on the wire.

## PQC claim boundary

The default/core sealing API does not require `xenia-wire` to establish keys:
callers may still install externally established session keys directly.

When the optional `handshake` feature is enabled, however, this crate also
ships pre-alpha handshake implementations in `src/handshake.rs` and
`src/handshake_highsec.rs`. The standard module provides the viewer-side
ML-KEM-768 + Ed25519 + ML-DSA-65 composition used for interoperability with the
native Xenia host stack; the high-security module uses ML-KEM-1024 + Ed25519 +
ML-DSA-87 and includes both roles.

Those optional modules are real cryptographic protocol surfaces and are in
scope for vulnerability reporting. Their presence does **not** make
`xenia-wire` a transport, a complete remote-control product, an independently
audited PQ-authenticated system, or a production-security certification. Product
layers such as `xenia-peer` retain their own authentication, authorization,
consent, transport, and effect-boundary responsibilities.

See `plans/FULL_PQC_BOUNDARY.md` before changing PQC wording in README,
release, or marketing text.

## Reporting a vulnerability

Please report security vulnerabilities through one of:

1. **GitHub Security Advisories** — preferred.
   <https://github.com/Luminous-Dynamics/xenia-wire/security/advisories/new>
   ensures the disclosure stays private until a fix is ready.

2. **Email** — `tristan.stoltz@evolvingresonantcocreationism.com` with
   subject `[xenia-wire SECURITY]`. PGP key fingerprint is published
   on the Luminous Dynamics website.

**Please do not open a public issue** for security-sensitive findings
until we've had a chance to respond.

## Scope

In scope:

- The wire format itself (envelope layout, nonce construction,
  domain separation, AEAD parameters).
- The replay window semantics (acceptance rules, too-old boundary,
  multi-stream isolation).
- Key lifecycle (rotation, grace period, zeroization, operator-rekey control
  semantics where enabled).
- The optional consent ceremony/state machine and its transcript/session
  binding.
- The optional `handshake` and `handshake_highsec` modules, including protocol
  composition, transcript binding, KEM/signature validation, and key schedule.
- Anything that would let a network attacker break confidentiality,
  integrity, authenticity, or replay protection.
- Denial-of-service findings with a concrete resource-exhaustion path.

Out of scope (for this repository):

- Handshake/product implementations that live only in other repositories or
  crates, including native host/product-layer behavior in `xenia-peer` that is
  not implemented by `xenia-wire`.
- Transport-layer attacks (TCP reset, WebSocket frame injection) —
  `xenia-wire` is transport-agnostic by design.
- Deployment-specific issues (misconfigured transports, leaked key material
  through application bugs) unless the root cause is in this crate.

## Response timeline

We aim to:

- Acknowledge report within **2 business days**.
- Provide an initial assessment within **7 business days**.
- Ship a fix or detailed mitigation plan within **30 calendar days**
  for confirmed vulnerabilities.

These targets are best-effort during pre-alpha — we are a small
research organization, not a corporate SIRT.

## Credit

With your permission we will credit you in the release notes and
in the paper's acknowledgements. Anonymous reports are accepted.

## Bounty

There is no monetary bug bounty at this time.

## PQC boundary validation

Run `scripts/check-pqc-boundary.sh .` before changing README, SECURITY,
SPEC, migration, or release wording that mentions post-quantum properties. The
check wraps the positive claim scan and the negative overclaim matrix so the
crate remains framed as an AEAD/replay/consent protocol with optional pre-alpha
handshake modules, not as a standalone post-quantum product-security layer.
