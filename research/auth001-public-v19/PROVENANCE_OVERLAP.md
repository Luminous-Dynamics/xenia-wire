# AUTH-001 overlapping-grant/provenance boundary — v22

v21's 557,280-case bounded equivalence corpus did not include multiple independently revocable grant instances that map to the same flat request key.

v22 adds that boundary.

## Result

Generated overlap corpus: **11,664 cases**.

- explicit-authority validator C vs provenance-aware conventional reference monitor B+: **0 admission disagreements**;
- C vs the old flat key-level reference monitor B: **662 admission disagreements**.

The first concrete counterexample is selective revocation. Two grant instances authorize the same `(subject, action, resource, session)` key. Revoking one instance while leaving the other valid cannot be represented faithfully by a single key-level revocation bit: fail-closed flattening over-revokes the valid sibling, while keeping the key live can under-revoke a request that presents the revoked grant instance.

## Interpretation

The meaningful distinction is not capability enforcement versus reference-monitor enforcement. A conventional reference monitor that preserves **per-grant identity and provenance** reproduces C's admission decisions over this generated overlap corpus.

The fair conventional comparator is therefore B+, not the lossy flat-key B.

## Claim boundary

Finite generated corpus plus explicit counterexamples. This is not a general proof, not a model result, and not evidence that capability enforcement is intrinsically safer than a provenance-aware conventional reference monitor.