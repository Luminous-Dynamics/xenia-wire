# Test vectors

Deterministic hex fixtures for cross-implementation validation.

## Format

Each vector ships as three files:

- `NN_description.txt` — human-readable explanation.
- `NN_description.input.hex` (or `.bincoded.hex` for LZ4) —
the plaintext fed into `Session::seal()`.
- `NN_description.envelope.hex` — the AEAD-sealed envelope
bytes that a receiver would open.

Hex files are 16 bytes per line, lowercase, no separators within
a line. Strip newlines and parse as a contiguous byte stream.

## Fixed parameters

All vectors share:

| Parameter | Value |
|-----------|-------|
| `source_id` | `58454e494154535420` (ASCII "XENIATST", 8 bytes) |
| `epoch` | `0x42` |
| `key` | `78656e69612d776972652d746573742d766563746f722d6b65792d3230323621` (ASCII "xenia-wire-test-vector-key-2026!", 32 bytes) |

## Vectors

| # | Name | What it exercises |
|---|------|-------------------|
| 01 | hello_frame | Canonical roundtrip, 12-byte UTF-8 payload. |
| 02 | input_pointer | `payload_type=0x11` domain separation vs vector 01. |
| 03 | empty_payload | Zero-length plaintext. |
| 04 | long_payload | 256-byte payload covering every byte value. |
| 05 | nonce_structure | Three sequential seals demonstrating seq counter increment. |
| 06 | lz4_frame | LZ4-before-AEAD (`--features lz4` only). |
| 07 | consent_request | ConsentRequest signed with a deterministic Ed25519 seed, draft-03 with mandatory session_fingerprint (`--features consent`). |
| 08 | consent_response | Approving ConsentResponse to vector 07 (distinct responder seed; same session_fingerprint). |
| 09 | consent_revocation | ConsentRevocation signed by the responder terminating the session (same session_fingerprint as vectors 07 + 08). |
| 10 | revocation_before_approval | Event-sequence fixture: `ConsentViolation::RevocationBeforeApproval` from both `AwaitingRequest` and `Requested`. draft-03. |
| 11 | contradictory_response | Event-sequence fixture: `ConsentViolation::ContradictoryResponse` in both directions (Approved→Denied and Denied→Approved). draft-03. |
| 12 | stale_response | Event-sequence fixture: `ConsentViolation::StaleResponseForUnknownRequest` from `AwaitingRequest`, `Requested`, and `Approved`. draft-03. |

## Regenerating

```console
$ cargo run --example gen_test_vectors --all-features
```

Vectors are version-stamped to `xenia-wire 0.2.0-alpha.1`
(SPEC draft-03). The consent fixtures (07/08/09) changed
canonically between draft-02 and draft-03 due to the addition
of `session_fingerprint` in the signed Core — bytes will not
match older draft-02 fixtures.
If a version bump changes the wire format, regenerate and
bump the spec version (SPEC.md §Version history) in the
same commit.

## How to use from another language

### Envelope vectors (01-09)

For each vector:

1. Parse the `.envelope.hex` file into a byte array.
2. Construct an AEAD decryption context with the fixed key.
3. Extract nonce from envelope bytes `[0..12]`.
4. Decrypt envelope bytes `[12..]` using ChaCha20-Poly1305.
5. Compare the decrypted plaintext against `.input.hex`.

If steps 1-5 succeed and the plaintext matches, your
implementation is byte-compatible with `xenia-wire` for that
scenario.

### Event-sequence vectors (10-12)

These fixtures do not ship envelope or input hex files; they
are line-oriented scripts that exercise your `observe_consent`
analogue. The grammar is fully documented inside
`10_revocation_before_approval.txt`. Parse after the
`---BEGIN---` marker and drive your state machine one EVENT at
a time, asserting EXPECT_STATE / EXPECT_VIOLATION as you go.

The reference implementation's runner is in
`tests/violation_vectors.rs`; an alternate-language runner
should replicate the same assertions to validate draft-03
compliance.
