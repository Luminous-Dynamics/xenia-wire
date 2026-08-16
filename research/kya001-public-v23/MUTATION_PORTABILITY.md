# KYA-001 arbitrary-fixture and adversarial mutation portability

The Python reference verifier and Node.js verifier accept arbitrary fixture paths, so new vectors can challenge the interface rather than being compiled into one canonical self-test.

Fifteen designed adversarial mutations cover subject substitution, session/context substitution, action/resource scope escalation, not-before/expiry violations, unknown/missing authority, signed-object tampering, direct/ancestor revocation, invalid attenuation, missing parent, provenance cycles, and parent-signature corruption.

Current local result: Python 15/15 expected outcomes/reasons; Node.js 15/15; cross-language disagreements 0.

This is local test-HMAC semantic evidence, not third-party implementation, production cryptographic security, standards-profile interoperability, privacy validation, or adoption.