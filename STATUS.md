# xenia-wire — Current Repository Status

<!-- repo-status: claims.toml -->

This file is the current human status entry point for repository-level maturity and claim boundaries. Registered claims are maintained in [`claims.toml`](claims.toml) and rendered in [`docs/CLAIMS.md`](docs/CLAIMS.md).

## Current status

- **Maturity:** pre-alpha.
- **Production ready:** no.
- **Independent security/cryptographic audit:** no.
- **Claims registry coverage:** partial.
- **Repository Conformance:** RC-1 for this source tree once the repository-integrity checker and its adversarial tests pass on the exact head; RC-1 is a repository-process statement, not a security certification.
- **Canonical branch protection:** not currently asserted by this profile; RC-3 is therefore not claimed.

## Scope boundary

The core/default API is an AEAD/replay-protected wire layer that can accept externally established session keys. Optional features add signed consent, handshake/high-security-handshake modules, and operator-rekey protocol surfaces.

The repository as a whole is still **not** a transport, a complete remote-control product, an independently audited PQ-authenticated system, or a production-security certification. See [`SECURITY.md`](SECURITY.md) for the current vulnerability-reporting and PQC boundary.

## Protocol authority

[`SPEC.md`](SPEC.md) draft-03 declares itself the normative reference for the **wire protocol**. That statement does not automatically extend the wire spec's qualification boundary to optional handshake modules bundled in the crate.

The repository publishes deterministic fixtures under [`test-vectors/`](test-vectors/) and includes non-Rust conformance checkers under [`test-vectors/conformance/`](test-vectors/conformance/). The exact coverage and limitations currently registered for those surfaces are in `claims.toml`.

## Historical/currentness rule

Repository history, old release notes, prior README wording, or older qualification runs do not silently acquire authority over the current head.

```text
historical claim
    !=
current claim

implemented feature
    !=
qualified feature

internal cross-implementation check
    !=
external replication or audit
```

When these distinctions change, update the machine-readable registry and its evidence first; the generated human claim surface must then change deterministically with it.
