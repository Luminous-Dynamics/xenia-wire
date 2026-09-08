# AUTH-001 public evidence — v22

This draft-review branch publishes AUTH-001 instrument evidence against reviewed `xenia-wire` main `98bf5fcd8bc540fccec66a64793851802e3b1bde`.

## Current evidence

- 10,000/10,000 generated matched B/C authorization cases agree in the original fairness corpus.
- Adaptive toy red-team rediscovered a shared parent-revocation bug in both legacy implementations; the matched repair closes it in the configured search.
- 5,000 generated metamorphic cases across 50 seeds produced 0 invariant failures in the tested properties.
- A bounded exhaustive checker covers **557,280 matched cases** with **0 B/C admission disagreements** in its finite non-overlap domain and detects a seeded ancestor-revocation defect.
- v22 adds **11,664 overlapping-grant cases**. C disagrees with the old flat key-level B **662 times**, because flat keys cannot preserve independently revocable grant identity. A provenance-aware conventional reference monitor **B+ disagrees with C 0 times** in that corpus.

## Scientific correction

The strongest surviving thesis is not that capability enforcement is intrinsically better than a competent reference monitor. The important semantic requirement is preservation of **grant identity and lifecycle provenance** across delegation, selective revocation, expiry, compilation, execution, and audit.

The fair conventional comparator is therefore B+, an ordinary per-grant/provenance-aware reference monitor. The next 2×2 experiment crosses B+ vs C with flat lifecycle records vs an explicit delegation graph, while matching information content, controller API, tasks, seeds, decoding, and exogenous randomness.

## Interpretation

This is instrument and bounded semantic evidence. If B+ and C continue to tie while graph representation helps both, the result belongs to lifecycle representation/comprehensibility—not capability-backend superiority.

## Non-claims

This does not establish alignment, arbitrary-agent containment, general backend equivalence, capability superiority, production readiness, standards interoperability, or external reproduction.