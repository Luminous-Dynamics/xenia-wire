# Xenia Wire draft-03 — Normative Errata

This file records normative clarifications to `SPEC.md` that do **not** change
the draft-03 envelope bytes. It exists so security corrections can become
binding without pretending that an unchanged wire layout is a new protocol
draft. A future specification revision should fold these clarifications into
the main text and retire the corresponding errata entries.

## E-03-001 — Nonce uniqueness is per sealing role, not merely per local Session

**Applies to:** `SPEC.md` §3 and §3.1.

`source_id` is a **sender / sealing-role nonce domain**. It MUST NOT be treated
as a connection identifier that both directions automatically share.

For any fixed ChaCha20-Poly1305 traffic key, the complete 96-bit nonce MUST be
unique across **every encryption performed with that key**, including
encryptions performed by the opposite peer. Local monotonicity inside one
`Session` object is insufficient when two sealing roles share the same key.

Therefore, two sealing roles whose sequence spaces can overlap MUST NOT share
the tuple:

```text
(key, source_id[0..6], epoch, payload_type)
```

unless an outer protocol proves that their sequence values are globally
disjoint for the entire lifetime of that key. In particular, a conventional
bidirectional session in which both peers start or reset their local counters at
zero MUST give the two sealing directions distinct nonce domains.

### Required safe profiles

A bidirectional protocol that uses one symmetric traffic key for both directions
MUST do at least one of the following:

1. assign distinct `source_id[0..6]` values to the two sealing directions;
2. assign direction-specific traffic keys cryptographically derived for TX and
   RX; or
3. use another versioned construction that proves complete key/nonce uniqueness
   across both roles.

Option 2 is RECOMMENDED for future handshake profiles because it reduces the
number of nonce-allocation invariants that applications must enforce.

Different payload types already occupy different nonce domains because
`payload_type` is byte 6 of the nonce. That does **not** save a bidirectional
control stream when both peers seal the same payload type with the same key,
source prefix, epoch, and sequence.

### Rekey interaction

A **genuine different-key** `Session::install_key()` transition resets that local
sender's sequence counter to zero for the new cryptographic key domain. A
byte-identical reinstall of the current key is not a rekey and MUST preserve the
existing nonce/replay epoch state.

If both peers install the same genuinely new traffic key, then both peers can
immediately emit sequence `0`. A shared sender nonce domain would therefore
recreate a key/nonce pair across directions at the start of every new key epoch.

Applications MUST preserve directional separation across every genuine rekey.
They MUST NOT use duplicate installation of the current key as a mechanism for
resetting sender sequence or receive replay state.

### Receive-side source validation

The draft-03 Rust `Session::open()` authenticates the complete nonce because the
nonce participates in ChaCha20-Poly1305 verification, but it does not currently
require the nonce's `source_id` bytes to equal the receiving `Session` object's
stored `source_id`. Applications whose security policy binds a peer to a
particular sender nonce domain MUST enforce that binding before accepting the
opened plaintext, or use a strict receive API that enforces the expected sender,
payload, and epoch domain before replay-state mutation.

This receive-side clarification is separate from AEAD nonce uniqueness: a
cryptographically valid envelope can still come from an unexpected sender
nonce domain if that sender possesses the traffic key.

### Non-breaking status

E-03-001 changes no envelope field, nonce byte layout, AEAD algorithm, replay
window, payload assignment, or canonical signed body. It clarifies security
preconditions that follow from ChaCha20-Poly1305's requirement that a key/nonce
pair never repeat.

Executable regression evidence lives in
`tests/directional_nonce_contract.rs` and the duplicate-key lifecycle regression
in `tests/install_key_nonce_characterization.rs`.
