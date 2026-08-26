# Causal Authority v1 — Draft Extension Plan

**Status:** experimental, opt-in, not part of normative SPEC draft-03.

**Tracking:** #20

## Why this exists

Xenia draft-03 already signs a `ConsentRequestCore` containing:

- request ID;
- requester key;
- session fingerprint;
- consent expiry;
- session access scope;
- free-text reason;
- reserved `causal_binding`.

The signed `ConsentResponseCore` independently approves or denies the same
ceremony by `request_id` and `session_fingerprint`.

That is a strong basis for external authority, but draft-03 requires
`causal_binding = None`. Neither `ConsentScope` nor the free-text reason is a
safe machine-readable authorization for one exact consequential action.

This extension activates the reserved slot without changing the existing signed
struct layout. It remains feature-gated until compatibility and conformance are
proven and the normative specification decides whether it belongs in draft-03.x
or draft-04.

## Profile identifier

Human-readable predicate description:

`xenia.external-action-authority.v1`

Opaque bytes:

`b"xenia.external-action-authority.v1\0" || bincode_v1(ExternalActionAuthorityV1)`

The NUL terminator is part of the domain separator. A verifier must reject a
predicate unless both the exact description and exact opaque prefix match.

After decoding, the verifier re-serializes the semantic payload and requires
byte-for-byte equality with the original bytes. Trailing or non-canonical data
therefore fails closed.

## Semantic payload

```rust
ExternalActionAuthorityV1 {
    subject_id: [u8; 16],
    target: String,
    capability: String,
    action_digest: [u8; 32],
    parameters_digest: [u8; 32],
    max_scope: String,
    expires_at_ms: u64,
    use_policy: AuthorityUsePolicy,
}
```

The strings are application identifiers, not natural-language permission
claims. Consumers must define and compare their own canonical target,
capability, and scope representations exactly.

`subject_id` is caller-defined and must be non-zero. A common mapping is the
16-byte representation of an immutable action-intent UUID.

`action_digest` and `parameters_digest` must hash canonical representations.
Xenia deliberately does not define those downstream canonicalizations.

The authority expiry must not exceed the enclosing signed consent-request
expiry.

## Complete approval verification

An external-action authority is not established by a ledger `Approval` or a
`ConsentResponse` alone.

`verify_approved_external_action_authority` requires:

1. valid signed `ConsentRequest` from the expected requester key;
2. valid signed `ConsentResponse` from the expected responder key;
3. equal request IDs;
4. both signed messages bound to a caller-supplied trusted session fingerprint;
5. `approved == true`;
6. unexpired consent request;
7. supported, canonical causal-authority profile;
8. unexpired action authority that does not outlive consent;
9. no supplied valid matching revocation.

The expected session fingerprint must come from a trusted live-session or
transcript-verification path. Merely comparing the request's embedded
fingerprint to the response's embedded fingerprint is not enough to prove that
the pair belongs beside the intended session.

## Revocation

A matching revocation is one with the same request ID and expected session
fingerprint. It is accepted only when:

- the revoker is either the expected requester or expected responder;
- its signature verifies;
- its issue timestamp is not in the future relative to verification time.

A valid matching revocation terminates the authority.

The verifier can only reason about revocations supplied by its caller. Evidence
systems must therefore provide the complete relevant revocation view from the
canonical ledger/session evidence source.

## Replay and single-use

`AuthorityUsePolicy::SingleUse` is the conservative policy for consequential
machine mutations.

The wire library cannot durably know whether an external action was already
executed on another process or after a restart. A consumer accepting single-use
authority must atomically/durably mark `subject_id` consumed before or together
with the consequential action.

`SessionBoundReusable` permits repeated use only for the exact bound subject
inside the same Xenia session until expiry or revocation. It must never be
interpreted as bearer authority outside that session.

## What this does not claim

This draft does not yet establish:

- draft-03 wire compliance for non-`None` causal bindings;
- backward interoperability with older peers;
- cross-language reproduction of the new opaque bytes;
- integration with `xenia-ledger` evidence bundles;
- durable single-use enforcement;
- production readiness.

## Promotion gates

Before this extension becomes normative:

- freeze whether activation is draft-03.x or draft-04;
- add deterministic profile vectors;
- reproduce those vectors independently (the existing JS conformance harness is
  a natural second implementation);
- test an old peer receiving a non-`None` causal binding and document the exact
  fail/accept behavior;
- connect the approved authority to transcript-bound ledger evidence;
- add revocation and replay/consumption integration tests;
- update `SPEC.md` and `CHANGELOG.md` only after those compatibility decisions
  are explicit.

Until then, the `causal-authority` Cargo feature is an experimental research
surface and callers must not advertise it as draft-03-conformant external
authorization.
