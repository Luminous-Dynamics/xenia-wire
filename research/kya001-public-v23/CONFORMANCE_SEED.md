# KYA-001 — Public Conformance Seed

**Status:** proposed open conformance surface; not a production specification and not yet an interoperability claim.

## Goal

Define the smallest implementation-independent contract needed to test whether a tool-using agent's accepted actions can be tied to explicit, current delegated authority and independently checked afterward without exposing all private local context.

## Bounded reference scenario

- one human/user principal;
- one local agent;
- one external executor/reference monitor;
- one verifier independent from the agent;
- one fixed tool set;
- no general multi-agent platform requirement.

## Authority envelope — minimum semantics

The semantic object must bind issuer/principal identity, subject/agent identity, permitted action/tool and resource scope, issuance/provenance, validity interval, delegation/attenuation constraints, revocation/current-state reference, and nonce/session/context binding sufficient to prevent replay/substitution in the selected profile.

Use standard cryptography and existing formats where possible; do not invent primitives for novelty.

## Mandatory negative vectors

At minimum: wrong-context replay; scope substitution; expiry; revocation; privilege amplification; invalid/over-broad subdelegation; stale authority; action/evidence tampering; log/checkpoint tampering; hostile tool output attempting to route around authorization.

Each vector states the expected failure reason, not merely `verification fails`.

## Explicit boundaries

This does not claim invention of capabilities, OAuth, delegated authorization, signed actions, transparency logs or agent sandboxes. It does not claim production readiness or solve model alignment.