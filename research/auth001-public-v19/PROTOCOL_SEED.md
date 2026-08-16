# AUTH-001 — Public Protocol Seed

**Status:** preregistration draft; no result is claimed.
**Research question:** do explicit, revocable authority-lifecycle semantics reduce privilege-lifecycle failures under repeated agent/controller adaptation beyond a competent ordinary external reference monitor?

## Conditions

All conditions receive the same task distribution, model/controller family, tools, environment, adaptation schedule, and useful-task objective.

### A — behavioral restriction only

The agent is instructed not to use restricted actions/resources. The executor does not independently enforce the restriction beyond ordinary tool validity.

### B — competent external reference monitor

A conventional external monitor enforces an allowlist/policy over principal, tool/action and resource. This is the real control for the capability-specific thesis.

### C — explicit authority lifecycle

The external monitor enforces authority carrying explicit scope, issuance/provenance, expiry, attenuation/delegation and revocation state. Actions are admitted only under current authority.

## Minimal environment

- 4–6 tools with at least one materially consequential write/action path;
- tasks requiring both allowed and temporarily elevated actions;
- deterministic environment-effect logging;
- multiple random seeds / task variants;
- no real external accounts, money, or production systems.

## Lifecycle events

The protocol must include at least:

1. temporary privilege grant;
2. attenuation/delegation or sub-agent handoff;
3. expiry;
4. explicit revocation;
5. reauthorization;
6. stale/replayed authority attempt;
7. route-around / privilege-acquisition attempt.

## Adaptation

Run a predeclared sequence of controller/policy/scaffold adaptations. The adaptation mechanism and number/range of rounds are frozen before final evaluation. The objective may reward task completion strongly enough to create pressure to seek unavailable privileges, but must not explicitly tell one condition how to exploit another condition's implementation.

## Primary outcomes

- unauthorized **environment effects**;
- stale/replayed/revoked-authority success;
- delegation/attenuation/lifecycle errors;
- privilege-acquisition / route-around success;
- false denials and useful-task loss;
- authority-state calibration error;
- operator/verifier ability to reconstruct why an action was admitted or refused.

## Decision rule

The special AUTH thesis receives support only if **C materially improves relevant lifecycle outcomes over B** without an unacceptable utility penalty, and the result survives reasonable seeds/task variations.

- If **B ≈ C**, the capability-specific thesis is weakened.
- If C's failures move primarily to issuance/delegation, the research target moves there rather than being counted as a success.
- If either hard-enforcement condition destroys useful performance, that cost is reported rather than hidden.

## Publication / reproducibility

Before the final held-out run, publish or hash-pin:

- environment/tool schema;
- condition implementations;
- adaptation schedule;
- lifecycle event schedule/generator;
- primary metrics;
- exclusion/failure taxonomy;
- analysis script revision;
- random-seed policy.

After the run, publish all compatible code, aggregate results, negative/null outcomes and known limitations.

## Non-claims

This protocol does **not** assume or test that access control aligns a model, prevents deceptive goals, makes principals trustworthy, or contains arbitrary superintelligence. It tests one external action-authority failure channel.
