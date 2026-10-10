# Causal Authority v1 — Draft Extension Plan

**Status:** experimental; proposed draft-04 surface; not normative draft-03.

**Tracking:** #20

## Purpose

Xenia needs a cryptographic statement stronger than "this session request id was
approved" before downstream systems can treat consent as authority for a
consequential external mutation.

The target property is:

> the responder approved this exact requester-authenticated request, carrying
> this exact machine-readable action subject, for this exact Xenia session,
> before its expiry, and no valid revocation supersedes that approval.

Sovereign Ops, Nixward, Mycelix, and other consumers should consume this verified
Xenia authority substrate rather than inventing parallel signature formats.

## Why ordinary draft-03 consent is insufficient

`ConsentRequestCore` is already strong: its requester signature covers request
id, requester key, session fingerprint, expiry, session scope, reason, and the
reserved `causal_binding` field.

However, draft-03 `ConsentResponseCore` signs request id + responder key +
session fingerprint + decision + reason. It does **not** commit to the exact
request body.

That creates a request-substitution ambiguity for offline/external authority:

1. requester signs benign request A;
2. responder approves request id 7 in session F;
3. requester also signs more powerful request B with the same id 7 and F;
4. A and B are both valid requester-signed objects;
5. the ordinary response does not cryptographically identify which body was
   approved.

The live consent state machine can remember which request it observed, but an
exported authority proof must be self-authenticating. Exact external authority
therefore MUST NOT be inferred from an ordinary `ConsentResponse`.

## Compatibility decision

Treat activation as a **draft-04 candidate**, not draft-03.x.

Reasons:

- draft-03 normatively requires `causal_binding = None`;
- exact authority introduces a new signed response payload (`0x24`);
- old receivers must not silently reinterpret a non-None causal binding;
- explicit capability negotiation is safer than depending on incidental
  deserialization compatibility.

Until a draft-04 spec is frozen, `causal-authority` remains an experimental Cargo
feature and must not be advertised as draft-03 external authorization.

## 1. Machine-readable action subject

Profile description:

`xenia.external-action-authority.v1`

Opaque bytes:

`b"xenia.external-action-authority.v1\0" || bincode_v1(ExternalActionAuthorityV1)`

The NUL byte is part of the domain separator.

```rust
ExternalActionAuthorityV1 {
    subject_id: [u8; 16],
    target: Vec<u8>,
    capability: Vec<u8>,
    action_digest: [u8; 32],
    parameters_digest: [u8; 32],
    max_scope: Vec<u8>,
    expires_at_ms: u64,
    use_policy: AuthorityUsePolicy,
}
```

### Canonical identifier rule

`target`, `capability`, and `max_scope` are canonical application bytes, not
Unicode permission strings. Each consuming profile defines its own byte
canonicalization and compares the bytes exactly.

This avoids case-folding, Unicode normalization, path aliasing, and equivalent
serialization disagreements becoming authorization broadening bugs.

Each identifier is bounded to 1024 bytes. The complete causal payload is bounded
to 8 KiB. Empty identifiers fail closed.

`action_digest` and `parameters_digest` are non-zero 32-byte digests of canonical
application representations. An empty parameter set is represented by the hash
of an explicitly canonical empty value, not the all-zero sentinel.

Human-readable explanation belongs in signed `reason` fields and is never a
machine authorization input.

## 2. Exact signed-request digest

A responder approving external authority computes:

```text
request_digest = SHA-256(
    b"xenia.causal-authority.request-digest.v1\0" ||
    bincode_v1(complete_signed_ConsentRequest)
)
```

The complete request includes the requester signature, not merely
`ConsentRequestCore`.

This binds the responder to one exact requester-authenticated object and remains
well-defined even if a future requester signature algorithm is randomized.

## 3. Bound authority response (`0x24`)

The extension reserves payload type `0x24` for:

```rust
CausalAuthorityResponseCore {
    request_id: u64,
    request_digest: [u8; 32],
    responder_pubkey: [u8; 32],
    session_fingerprint: [u8; 32],
    approved: bool,
    issued_at_ms: u64,
    reason: String,
}
```

The responder signs the canonical bincode serialization of this core with its
Ed25519 device key.

Field order is load-bearing and must be frozen by the normative draft before
interoperability claims.

A normal draft-03 `ConsentResponse` can continue to serve ordinary session
consent. It is intentionally the wrong Rust type for exact external authority.

## 4. Complete verification contract

A verifier claiming `VerifiedExternalActionAuthority` MUST perform all of these
checks before returning authority:

1. verify the requester signature against the expected requester key;
2. require the request fingerprint to equal a trusted locally derived or
   transcript-verified session fingerprint;
3. require a supported canonical causal-authority profile;
4. verify all profile shape/size rules;
5. verify the bound-response signature against the expected responder key;
6. require equal request ids;
7. require the response fingerprint to equal the trusted session fingerprint;
8. recompute the digest of the complete signed request and require exact equality
   with `response.request_digest`;
9. reject zero or implausibly future response issue times;
10. require the response to have been issued before both consent expiry and
    action-authority expiry;
11. require the consent request to be unexpired at verification time;
12. require the action authority to be unexpired and not outlive the consent
    request;
13. require `approved == true`;
14. evaluate the complete relevant revocation view;
15. return exact bound fields plus a stable approval-instance id.

The expected session fingerprint MUST come from a trusted live-session or
transcript verification path. Merely comparing embedded request/response
fingerprints to each other is insufficient.

## 5. Authority instance id and single-use consumption

For one signed approval instance:

```text
authority_id = SHA-256(
    b"xenia.causal-authority.instance-id.v1\0" ||
    request_digest ||
    responder_pubkey ||
    response_signature
)
```

`AuthorityUsePolicy::SingleUse` means consumers MUST durably consume
`authority_id`, not merely caller-defined `subject_id`.

Recommended downstream state machine:

```text
Available
   |
   | durable reserve(authority_id, execution_id)
   v
Reserved
   |--------------------\
   | success             | crash/uncertain outcome
   v                     v
Consumed              RecoveryRequired
(receipt digest)         (fail closed)
```

A consumer must not execute first and mark consumed later. Reservation and the
start of consequential execution must be crash-consistent enough that a restart
cannot replay an ambiguous authorization.

Xenia deliberately does not own this durable store; it supplies the stable
cryptographic key that downstream execution ledgers consume.

`SessionBoundReusable` is weaker and must only be accepted by profiles that
explicitly permit repeated use inside the exact bound Xenia session. It must not
be converted into bearer authority outside that session.

## 6. Revocation semantics

Existing signed `ConsentRevocation` remains authoritative for this experimental
profile when request id + trusted session fingerprint match and the revoker is
one of the expected parties.

Because the legacy revocation does not carry `request_digest`, a valid matching
revocation conservatively revokes **all exact authorities associated with that
request id in that session**. This is fail-safe in the presence of duplicate-id
ambiguity.

A matching revocation with an unknown signer, invalid signature, or implausibly
future issue time is a hard verification error, not something to ignore.

The verifier can reason only about revocations supplied to it. Evidence systems
therefore must provide the complete relevant canonical revocation view.

A future draft may add a digest-bound revocation type if finer-grained
revocation becomes necessary; v1 should prefer conservative broad revocation.

## 7. Wire dispatch

`CausalAuthorityResponse` is sealed under payload type `0x24`.

The dedicated open helper checks the cleartext payload-type byte before AEAD
open/deserialization. A bincode-compatible payload from another stream must not
be accepted as an authority response merely because it can decode into the same
shape.

## 8. Resource bounds

The experimental profile adds explicit bounds even though existing consent
messages predate them:

- canonical target/capability/scope: <= 1024 bytes each;
- causal opaque payload: <= 8 KiB;
- authority request reason accepted by verifier: <= 4 KiB;
- bound response reason: <= 4 KiB;
- serialized bound response: <= 16 KiB.

The normative draft should specify decode-time allocation limits for all new
variable-length fields.

## 9. Required adversarial tests

Before promotion:

- [x] exact bound request/approval round trip
- [x] two valid same-id/same-session requests cannot share one approval
- [x] post-signature action mutation rejected
- [x] response for another request id rejected
- [x] denial rejected as authority
- [x] authority cannot outlive consent request
- [x] response issued after action expiry rejected
- [x] zero response issue time rejected
- [x] implausibly future response rejected
- [x] unknown causal profile fails closed
- [x] oversized canonical identifier rejected
- [x] wrong trusted session fingerprint rejected
- [x] valid matching revocation terminates authority
- [x] bound response is `Sealable`
- [x] `0x24` wire round trip + payload-type check
- [x] wrong payload type rejected before authority decode
- [x] distinct signed approval instances derive distinct `authority_id`s
- [ ] response signature substitution rejected explicitly
- [ ] requester key substitution rejected explicitly
- [ ] responder key substitution rejected explicitly
- [ ] truncated/non-canonical opaque payload vectors
- [ ] boundary-size vectors for all variable fields
- [ ] rekey-grace/session-fingerprint interaction
- [ ] revocation-before/after-response ordering vectors
- [ ] durable single-use crash/recovery integration in a downstream executor

## 10. Interoperability gates

Do not promote this surface until all of the following are evidence-backed:

- [ ] Rust unit/integration tests green with `causal-authority` explicitly enabled
- [ ] MSRV build green with `causal-authority`
- [ ] wasm32 build green with `causal-authority`
- [ ] deterministic request/profile/response vector committed
- [ ] independent Node/JS implementation reproduces canonical bytes, request
      digest, Ed25519 verification, and authority instance id
- [ ] old draft-03 peer behavior with non-None `causal_binding` captured
- [ ] explicit capability-negotiation rule for draft-04 peers
- [ ] transcript-bound ledger evidence integration specified
- [ ] downstream durable single-use consumption demonstrated
- [ ] SPEC.md updated only after the compatibility decision is frozen
- [ ] CHANGELOG claims match the evidence exactly

## 11. Downstream rule

`Luminous-Dynamics/sovereign-ops#10` remains blocked from claiming real Xenia
external-action authorization until this profile (or an equivalent stronger
mechanism) passes its interoperability gates.

Sovereign Ops should map its frozen action intent into the canonical authority
subject, verify Xenia's complete bound proof, durably reserve the returned
`authority_id`, execute, and then bind the execution receipt back to that same
id.
