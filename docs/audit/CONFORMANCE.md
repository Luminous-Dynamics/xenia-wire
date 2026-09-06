# Independent Wire Conformance

This directory is the first implementation-independent conformance lane for
`xenia-wire` draft-03.

## Trust boundary

The Python reference does **not** import the Rust crate, call Cargo, load a
native library, or share protocol helper code with `src/`.

Its ChaCha20-Poly1305 implementation is written directly from RFC 8439 using
only the Python standard library. A published RFC known-answer test anchors the
crypto implementation independently of Xenia before it is allowed to check any
Xenia fixture.

The Xenia inputs are the normative specification and frozen data under
`test-vectors/`.

```text
                   SPEC.md
                      |
         +------------+------------+
         |                         |
         v                         v
   Rust implementation       Python reference
         |                         |
         +----------+--------------+
                    |
             frozen vectors
```

Agreement is useful evidence of interoperability. It is not evidence that both
implementations are free of a shared specification defect.

## v0.1 coverage

The independent runner checks:

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
by the frozen 10-12 fixtures. Passing those fixtures must not be described as
qualification of every consent state transition.

## Run

From the repository root:

```console
python3 conformance/python/test_conformance.py
python3 conformance/python/xenia_wire_ref.py
python3 conformance/python/xenia_wire_ref.py --json
```

The JSON report is deterministic for unchanged repository bytes and includes the
exact SHA-256 of `SPEC.md` plus a deterministic digest over the vector directory.

## Claim boundary

A PASS means:

> an implementation written independently in Python reproduces the frozen
> draft-03 AEAD envelope fixtures, nonce-sequence fixture, and consent
> violation fixtures covered by this lane.

A PASS does **not** mean:

- production readiness;
- an external security audit;
- proof that the specification is correct;
- full handshake interoperability;
- independent LZ4 interoperability;
- full consent-state-machine coverage;
- validation of `xenia-peer` product semantics.

## Next

The next audit-readiness increments should add language-neutral transcript
fixtures for replay-window/key-lifecycle behavior and then extend independent
coverage to the handshake surfaces without sharing implementation code.
