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

## Regenerating

```console
$ cargo run --example gen_test_vectors --all-features
```

Vectors are version-stamped to `xenia-wire 0.1.0-alpha.1`.
If a version bump changes the wire format, regenerate and
bump the spec version (SPEC.md §Version history) in the
same commit.

## How to use from another language

For each vector:

1. Parse the `.envelope.hex` file into a byte array.
2. Construct an AEAD decryption context with the fixed key.
3. Extract nonce from envelope bytes `[0..12]`.
4. Decrypt envelope bytes `[12..]` using ChaCha20-Poly1305.
5. Compare the decrypted plaintext against `.input.hex`.

If steps 1-5 succeed and the plaintext matches, your
implementation is byte-compatible with `xenia-wire` for that
scenario.
