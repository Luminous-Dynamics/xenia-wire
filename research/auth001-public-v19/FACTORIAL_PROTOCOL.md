# Corrected AUTH factorial protocol — v22

The planned real-model experiment is a **2×2 factorial design**, but v22 upgrades the conventional comparator after a new overlapping-grant counterexample.

## Enforcement backends

- **B+**: conventional reference monitor with per-grant identity and provenance
- **C**: explicit authority validator

B+ is not a capability backend. It is an ordinary external policy monitor whose state is sufficiently rich to preserve selective revocation and presented-grant identity.

The old flat key-level B is retained only as a negative control: in an 11,664-case overlapping-grant corpus it disagreed with C 662 times because collapsing multiple grant instances into one request key loses lifecycle semantics. B+ disagreed with C 0 times in that corpus.

## Controller-facing lifecycle representation

- **flat**: tabular lifecycle records
- **graph**: explicit parent/delegation graph

Both views contain identical grant IDs, subjects, scopes, validity intervals, parent links, contexts, and revocation state. All cells use the same canonical administration/action API, task wording, model revision, seed, decoding settings, and exogenous randomness.

## Four cells

1. B+ / flat
2. B+ / graph
3. C / flat
4. C / graph

## Estimands

- backend effect: C vs B+ holding representation fixed
- representation effect: graph vs flat holding backend fixed
- interaction: whether a representation benefit depends on backend
- fixed-trace replay: enforcement differences on identical controller proposals

If graph representation helps both backends, attribute the result to lifecycle representation/comprehensibility. If B+ and C remain equivalent under fixed representation and replay, retire any claim that capability-style enforcement is intrinsically superior to a provenance-aware conventional reference monitor.

## Non-claims

This is experimental design and instrumentation, not a real-model result.