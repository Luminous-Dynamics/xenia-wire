# KYA-001 semantic preservation contract — v23

A backend adapter is conforming only if translation preserves the normalized authority decision over the supported lifecycle domain.

A conforming adapter must preserve at least:

1. grant identity — same-scope grants remain independently presentable/revocable;
2. subject/action/resource scope;
3. session/context binding;
4. not-before and expiry boundaries;
5. direct revocation;
6. parent/delegation provenance;
7. ancestor revocation and validity;
8. attenuation constraints;
9. authority-record integrity/signature state.

For every supported conformance vector, the source and compiled-backend decision must agree on admission. Where a normalized reason vocabulary is exposed, reason class should agree as well.

For each semantic dimension, include an intentionally lossy adapter or mutation. If removing that dimension never causes a relevant negative-vector failure, the conformance suite is underpowered for that semantic.

KYA does not require an ecosystem to replace its OAuth stack, sandbox, reference monitor, tool gateway, or capability executor. It requires the adapter boundary not to silently change authority meaning.