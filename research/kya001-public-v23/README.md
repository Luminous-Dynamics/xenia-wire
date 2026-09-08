# KYA-001 public evidence — v23

This draft-review branch publishes a bounded, backend-neutral authority-conformance surface against reviewed `xenia-wire` main `98bf5fcd8bc540fccec66a64793851802e3b1bde`.

## Current evidence

- canonical lifecycle fixture: 15 cases; two Python verifiers + Node.js agree on expected outcome/reason;
- adversarial mutation suite: 15 designed mutations, Python/Node expected results 15/15, 0 cross-language disagreements;
- v22 overlap boundary: naive flat key-level policy loses grant identity; provenance-aware conventional monitoring can preserve it;
- v23 compilation corpus: **174 lifecycle states / 11,130 requests**;
- lossless provenance-aware adapter vs explicit-authority oracle: **0 admission / 0 reason disagreements** in Python;
- independently implemented Node.js provenance-aware adapter on the same frozen corpus: **0 admission / 0 reason disagreements**;
- deliberately lossy adapters produce admission counterexamples when dropping parent provenance (95), session binding (853), validity (416), revocation (323), signature integrity (13), or grant identity via flat collapse (461).

## Product interpretation

KYA should be a **portable authority-lifecycle semantic layer plus conformance contract**, not a demand to replace existing sandboxes, OAuth/resource servers, policy engines, reference monitors, tool gateways, or capability executors. A backend is acceptable if its adapter preserves the normalized semantics and passes the negative vectors.

## Claim boundary

Finite local deterministic test-HMAC evidence only. This is not a formal proof, production cryptography, standards interoperability, adoption, external audit, or third-party reproduction.