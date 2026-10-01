# Authority capability provenance + rekey lineage v1

Status: **design candidate / not normative / not implemented**

Related: xenia-wire #20 / PR #21, xenia-peer #148 / PR #149

## Problem

Exact request-bound authority is necessary but not sufficient for a safe live execution API.

Today `Session` is intentionally a general-purpose AEAD state object. `Session::install_key` can replace its key, and authority verification accepts a plain `&Session` so it can authenticate consent fingerprints across the current and still-valid previous rekey keys.

That is correct at the low-level crypto boundary, but a higher-level application could make this mistake:

```text
authority-capable handshake
        -> set application bool authority_enabled=true
        -> unrelated Session::install_key(...)
        -> bool remains true
        -> authority policy accidentally survives a broken lineage
```

The fix is not another signature. The fix is making authority provenance and cryptographic session lineage one owned state machine.

## Distinguish provenance modes

Do not serialize every authority-capable session as merely `authority=true`.

Candidate provenance:

```text
AuthorityCapabilityProvenanceV1
  PinnedLegacy
    authenticated_handshake_transcript_hash
    pinned_selected_context_hash
    host_identity_fingerprint

  NegotiatedV2
    authenticated_handshake_transcript_hash
    base_v4_context_hash
    final_v5_context_hash
    host_offer_hash
    viewer_offer_hash
    selected_context_hash
    negotiation_binding_hash
    host_identity_fingerprint
```

`PinnedLegacy` means exactly: the legacy handshake authenticated a selected-context hash that the viewer expected out of band.

`NegotiatedV2` means exactly: both canonical peer offers were covered by the V2 ceremony, deterministic selection was independently recomputed, the V5 context matched on both sides, and finalize authentication succeeded.

Evidence, receipts, and policy must retain this distinction. A deployment may choose to permit pinned authority, but it must never label that mode `dynamically negotiated`.

## Authority lineage root

Derive a durable public lineage identifier from authenticated public evidence, not from session key bytes:

```text
lineage_id = SHA-256(
    "xenia.authority-lineage.v1\0" ||
    handshake_transcript_hash ||
    authority_context_hash ||
    host_identity_fingerprint
)
```

Where:

```text
PinnedLegacy authority_context_hash = pinned_selected_context_hash
NegotiatedV2 authority_context_hash = final_v5_context_hash
```

The lineage id is stable across authenticated rekeys and changes across a different handshake transcript, authority context, or host identity.

It is an audit identifier, not a secret and not an authorization token.

## Epoch evidence

The existing rekey protocol already provides the chain we need:

```text
base_transcript_hash
previous_epoch_hash
current epoch_hash
key_epoch
```

Do not invent a parallel authority rekey chain.

Authority session evidence should expose:

```text
AuthorityLineageEvidenceV1
  lineage_id
  provenance
  key_epoch
  previous_epoch_hash
  current_epoch_hash
```

Epoch 0 uses the authenticated handshake transcript as the chain root. Each accepted cryptographically derived rekey advances the existing Xenia epoch chain.

## Owned session states

Conceptual safe API:

```text
Session
  |
  | successful authenticated pinned or V2 handshake
  v
AuthenticatedSession<P>
  |
  | policy requires exact causal-authority draft-04
  v
AuthoritySession<P>
```

`P` is the provenance mode, not a boolean.

The authority wrapper **owns** the inner `Session`; callers do not receive mutable access that can call arbitrary `install_key` while retaining the authority marker.

Candidate safe surface:

```text
AuthoritySession::verify_request(...)
AuthoritySession::sign_response(...)
AuthoritySession::verify_authority(...)
AuthoritySession::apply_verified_rekey(...)
AuthoritySession::lineage_evidence()
AuthoritySession::into_unprivileged_session()
```

There is deliberately no:

```text
AuthoritySession::session_mut() -> &mut Session
AuthoritySession::install_key(arbitrary_key)
```

Dropping back to the raw/general-purpose Session consumes or invalidates the authority wrapper.

## Rekey transition

Only the existing verified rekey path may preserve authority state:

```text
AuthorityActive(epoch=N)
        |
        | receive authenticated proposal under valid current/grace key
        | independently verify proposal epoch hash
        | verify previous_epoch_hash == locally expected chain head
        | derive next key from authenticated rekey root + verified epoch hash
        v
AuthorityActive(epoch=N+1)
```

Any of these fail closed and do not advance authority state:

- proposal envelope fails AEAD authentication;
- epoch hash does not recompute;
- previous epoch hash mismatches;
- epoch number is stale/skipped contrary to policy;
- V5/provenance context changes;
- key is supplied directly rather than derived through the verified rekey function.

## Arbitrary key replacement

A general application may still need `Session::install_key`; do not break that API globally.

Instead, authority-aware code should have one of two behaviors:

1. the authority wrapper does not expose arbitrary installation at all; or
2. an explicit escape hatch consumes the authority state:

```text
AuthoritySession::replace_with_untrusted_key(key)
    -> Session
```

There must be no operation that returns another `AuthoritySession` after arbitrary key replacement.

## Rekey grace

Xenia already permits still-valid previous keys during a bounded grace window. Preserve this behavior.

The lineage state tracks the **current chain head**, while request fingerprint verification may accept current or grace-valid previous key material exactly as `Session::verify_consent_request` does today.

A request authenticated under the previous key immediately before rekey can therefore still be approved safely after rekey, but its authority receipt should identify the lineage plus the request/session fingerprint actually verified.

Do not rewrite an old request as though it originated under the new epoch.

## Exact authority execution receipt

A consequential execution receipt should bind at least:

```text
schema
lineage_id
authority provenance mode
handshake transcript hash
final authority context hash
key epoch / epoch hash
authority_id
request_digest
subject_id
target
capability
action_digest
parameters_digest
max_scope
use_policy
execution outcome
execution evidence digest
```

For `SingleUse`, durable reserve/consume remains downstream execution state:

```text
Available -> Reserved -> Consumed | RecoveryRequired
```

The reserve record should include `lineage_id + authority_id`, not `authority_id` alone, so recovery tooling can identify the exact authenticated session lineage that created the reservation.

## Cross-session replay rule

Even two sessions with identical selected capabilities or identical V5 contexts are different authority lineages because their authenticated handshake transcripts differ.

Therefore:

```text
proof/session A + request/session B -> reject
lineage A authority receipt replayed into lineage B -> reject
same V5 context across A and B -> insufficient to authorize replay
```

The existing session fingerprint remains the live cryptographic check; `lineage_id` is the durable public evidence/audit identifier.

## Proposed type-level narrowing

For V2:

```text
AuthenticatedNegotiatedHandshake
        |
        | require selected xenia.causal-authority/draft-04
        v
AuthenticatedCausalAuthorityHandshake
        |
        | install handshake-derived key into owned Session
        v
AuthoritySession<NegotiatedV2>
```

For legacy pinned mode:

```text
AuthenticatedPinnedCausalAuthorityContext
        |
        | explicit deployment policy permits pinned mode
        v
AuthoritySession<PinnedLegacy>
```

No implicit conversion between provenance modes.

## Failure/recovery states

For security-critical consumers, an authority session should distinguish:

```text
Active
RekeyPending
Invalidated
Closed
RecoveryRequired
```

`Invalidated` is terminal for authorization. A new authenticated handshake is required to regain authority capability.

`RecoveryRequired` is for ambiguous durable execution consumption, not for handshake/rekey failures. Do not solve uncertain execution by silently re-authorizing.

## Adversarial gates

Before promotion:

- authority proof from session A + live Session B -> reject;
- same V5 but different transcript -> different lineage id;
- same transcript bytes but different authority context -> different lineage id;
- different host identity -> different lineage id;
- verified rekey preserves lineage id and advances epoch chain;
- rekey proposal with wrong previous hash -> reject;
- rekey proposal with wrong epoch hash -> reject;
- arbitrary key installation cannot return/retain AuthoritySession;
- grace-valid previous-key request remains verifiable without changing its original fingerprint;
- expired previous key no longer verifies request;
- lineage receipt cannot be replayed as authority in another session;
- pinned provenance never renders as negotiated V2 provenance;
- `into_unprivileged_session()` irreversibly drops authority capability at the type level.

## Promotion order

1. V2 offer/selection/codec primitives green.
2. V2 authenticated handshake proof green.
3. V5 context binding green.
4. Introduce provenance + lineage evidence types.
5. Introduce owned `AuthoritySession` wrapper.
6. Route rekey only through the existing verified epoch-chain path.
7. Add arbitrary-key invalidation/type-level escape tests.
8. Bind authority receipts to lineage evidence.
9. Demonstrate downstream durable single-use recovery.
10. Only then permit production-facing claims of negotiated external-action authority.
