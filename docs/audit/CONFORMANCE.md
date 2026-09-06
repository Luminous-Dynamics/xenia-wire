# Independent Wire Conformance

`xenia-wire` already has one implementation-independent conformance path under
`test-vectors/conformance/`: Node.js checkers independently open/seal envelope
vectors 01-09 and replay consent vectors 10-12, and ordinary repository CI runs
them.

This directory adds a **second independently constructed oracle** for draft-03.
The goal is triangulation, not replacement.

## Trust boundary

The Python reference does **not** import the Rust crate, call Cargo, load a
native library, or share protocol helper code with `src/`.

Its ChaCha20-Poly1305 implementation is written directly from RFC 8439 using
only the Python standard library. A published RFC known-answer test anchors the
crypto implementation independently of Xenia before it is allowed to check any
Xenia fixture.

That differs materially from the existing Node checker, which delegates the
AEAD primitive to Node's built-in crypto implementation. Both approaches are
valid; agreement between them reduces one class of common-mode implementation
risk.

The evidence shape is:

```text
                         SPEC.md
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
        Rust crate      Node checker   Python oracle
                           |              |
                    built-in crypto   RFC 8439 code
             |              |              |
             +--------------+--------------+
                            |
                      frozen vectors
```

Agreement is useful interoperability evidence. It is not evidence that all
implementations are free of a shared specification or fixture defect.

## v0.1 coverage

The Python oracle checks:

- every `*.envelope.hex` fixture that has a frozen plaintext input;
- exact ChaCha20-Poly1305 authentication and decryption;
- deterministic resealing to the exact published envelope bytes;
- Xenia nonce parsing and round-trip encoding;
- vector 05 sequence bytes `[0, 1, 2]` with a stable source/type/epoch prefix;
- the line-oriented draft-03 consent violation fixtures 10, 11, and 12;
- deterministic SHA-256 identities for `SPEC.md` and the complete vector set.

Vector 06 is intentionally checked at the AEAD boundary: the expected plaintext
is the frozen `.lz4_compressed.hex` fixture. v0.1 does not independently
reimplement LZ4.

The consent reference is intentionally limited to the transition rows exercised
by frozen vectors 10-12. Passing those fixtures must not be described as
qualification of every consent state transition.

## Existing Node conformance

The existing authority remains visible and should not be duplicated or hidden:

```console
node test-vectors/conformance/verify.mjs
node test-vectors/conformance/verify-consent.mjs
```

Those commands are already part of ordinary `CI`.

## Python oracle

From the repository root:

```console
python3 conformance/python/test_conformance.py
python3 conformance/python/xenia_wire_ref.py
python3 conformance/python/xenia_wire_ref.py --json
```

The JSON report is deterministic for unchanged repository bytes and includes the
exact SHA-256 of `SPEC.md` plus a deterministic digest over the vector directory.

## Claim boundary

A Python PASS means:

> a second implementation, written independently in Python and anchored to an
> RFC 8439 known-answer vector, reproduces the frozen draft-03 AEAD envelope
> fixtures, nonce-sequence fixture, and consent violation fixtures covered by
> this lane.

Together with the existing Node lane, this can support a **three-path agreement**
claim (Rust + Node + Python) only after the exact Python candidate is hosted and
green. It is not an external audit.

A PASS does **not** mean:

- production readiness;
- an external security audit;
- proof that the specification is correct;
- full handshake interoperability;
- independent LZ4 interoperability;
- full consent-state-machine coverage;
- validation of `xenia-peer` product semantics.

## Next

The next audit-readiness increment should add language-neutral transcript
fixtures for replay-window/key-lifecycle behavior and require both non-Rust
implementations to consume them independently. Handshake surfaces should follow
only after their protocol-visible state/serialization contracts have equivalent
frozen fixtures.
