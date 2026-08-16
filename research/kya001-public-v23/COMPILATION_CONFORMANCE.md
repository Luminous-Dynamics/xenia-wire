# KYA-001 executable compilation conformance — v23

v23 turns the backend-neutral compilation thesis into executable differential evidence.

## Frozen test surface

- canonical KYA lifecycle fixture: 15 cases;
- generated compiler corpus: **174 lifecycle states / 11,130 requests**;
- overlap, delegation, expiry, revocation, malformed provenance, signature corruption, and context/scope substitutions.

## Lossless conventional adapter

A provenance-aware conventional reference monitor preserves grant identity, scope, context, validity, revocation, parent provenance, attenuation, and integrity state.

Results:

- Python adapter vs explicit-authority oracle: **0 admission disagreements / 0 reason disagreements** over 11,130 generated cases;
- canonical fixture: **15/15 exact outcome + reason agreement**;
- independently implemented Node.js adapter over the same frozen corpus: **0 admission disagreements / 0 reason disagreements**.

## Deliberately lossy adapters

Admission disagreements when one semantic dimension is discarded:

- parent/delegation provenance: **95**;
- session/context binding: **853**;
- validity interval: **416**;
- revocation state: **323**;
- signature/integrity state: **13**;
- grant identity via flat ACL collapse: **461**.

The local report preserves a concrete admission counterexample for every lossy transform.

## Interpretation

The product boundary is a portable authority-lifecycle representation plus a semantic-preservation contract and negative conformance tests for adapters into existing enforcement.

## Claim boundary

Finite local synthetic/test-HMAC evidence only. Not a formal proof, production security validation, standards interoperability result, external audit, or third-party reproduction.