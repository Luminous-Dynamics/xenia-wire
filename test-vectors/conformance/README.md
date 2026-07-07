# Cross-implementation conformance checker

`verify.mjs` is an **independent, non-Rust** implementation of the
`xenia-wire` envelope open/seal path, written against `SPEC.md` §2–§3 and the
committed test vectors. It exists to make the "byte-deterministic across
implementations" claim testable rather than asserted: until now every consumer
of the vectors was Rust (and the only cross-implementation test was
Rust-native-vs-Rust-WASM, sharing crates), so nothing validated that a *second,
independent* implementation reproduces the same bytes.

It uses only Node.js's built-in `crypto` (ChaCha20-Poly1305) — no external
dependencies, and no `xenia-wire` code.

## What it proves

For each of the nine envelope vectors (01–09) it runs a **bidirectional**
check:

1. **open** — AEAD-decrypt `envelope[12..]` under the fixed key with
   `nonce = envelope[0..12]`; assert the plaintext equals the committed input.
2. **seal** — AEAD-encrypt that same input under the same key + nonce; assert
   the produced envelope is **byte-identical** to the committed one. This is
   the determinism proof: a conforming implementation must reproduce the exact
   bytes, which pins the nonce layout, AEAD parameters (empty AAD), and the
   `nonce ‖ ciphertext ‖ tag` framing.
3. **shape** — assert the nonce matches SPEC §3: `source_id[0..6]` constant
   across all vectors, `epoch` byte `== 0x42`, payload-type byte matches the
   registry, length `>= 28`.

Plus a tamper check (a flipped ciphertext byte must fail Poly1305
authentication) to confirm the tag is verified, not merely parsed.

`verify-consent.mjs` is the companion for the consent event-sequence vectors
(10–12). It reimplements the `observe_consent` state machine from SPEC §12.6.1
(the normative transition table) and replays each vector's line-oriented DSL,
asserting EXPECT_STATE / EXPECT_VIOLATION exactly as the Rust reference runner
(`tests/violation_vectors.rs`) does — covering the RevocationBeforeApproval,
ContradictoryResponse (with prior/new), and StaleResponseForUnknownRequest
violation paths.

## Run

```console
$ node test-vectors/conformance/verify.mjs          # envelope vectors 01–09
$ node test-vectors/conformance/verify-consent.mjs  # consent vectors 10–12
```

Both exit non-zero on any mismatch. No build step, no `npm install`. CI runs
both.

## Scope

Covers all twelve vectors: the envelope wire format (01–09) and the consent
state machine (10–12). One narrow gap remains:

- **LZ4 decompression** (vector 06): `verify.mjs` validates the AEAD layer for
  the `FRAME_LZ4` payload type (decrypt/reseal of the already-compressed
  plaintext) but does not reimplement LZ4 itself. The Rust vectors cover
  compress/decompress.

If a wire-format or state-machine change regenerates the vectors, these
checkers should keep passing unchanged — if they don't, either the change is a
genuine breaking bump (bump the SPEC version) or the checker caught a
determinism/semantics regression.
