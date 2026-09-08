# Bounded exhaustive B/C equivalence — v21

The corrected AUTH reference-monitor backend (B) and explicit-authority backend (C) were exhaustively compared over a finite matched-policy domain using the actual benchmark implementations.

## Result

- direct matched cases: **138,240**
- valid one-level delegated cases: **419,040**
- total cases: **557,280**
- B/C admission disagreements: **0**
- seeded ancestor-revocation defect: **detected**

The domain spans subjects, actions, resources, sessions, validity intervals, evaluation steps, direct/ancestor revocation, request mutations, and one level of valid delegation/attenuation.

## Interpretation

This substantially strengthens the null baseline: within this bounded domain, corrected B and C are functionally equivalent enforcement kernels.

It therefore weakens any framing in which C is expected to win merely because it is an explicit capability/authority representation. The next experiment must separate **enforcement backend** from **controller-facing lifecycle representation**.

## Non-claims

This is a bounded finite-state result, not a general proof of equivalence, not a model-controller result, and not evidence that either design solves alignment or advanced-agent control.
