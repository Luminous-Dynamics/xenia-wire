# Security Policy

`xenia-wire` is a cryptographic protocol implementation. We take
vulnerabilities seriously and appreciate responsible disclosure.

## Status

`0.1.0-alpha.x` is **pre-alpha**. The wire format is not yet frozen,
the specification document is not yet written, and no independent
cryptographic review has occurred. Do not deploy in production.

That said — if you find something worth knowing, we want to know
it now rather than after others depend on the wire.

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
- Key lifecycle (rotation, grace period, zeroization).
- Anything that would let a network attacker break confidentiality,
  integrity, authenticity, or replay protection.
- Denial-of-service findings with a concrete resource-exhaustion path.

Out of scope (for now):

- The handshake — `xenia-wire` takes keys as input; handshake
  vulnerabilities live in the handshake layer (not yet published).
- Transport-layer attacks (TCP reset, WebSocket frame injection) —
  `xenia-wire` is transport-agnostic by design.
- Any deployment-specific issue (misconfigured transports, leaked
  key material through application bugs).

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
