# Authority activation evidence v1

Status: **design candidate / non-normative / not implemented**

Related: xenia-wire #20 / PR #21, xenia-peer #148 / PR #149

## Purpose

Authenticated capability negotiation, cryptographic session lineage, and local acceptance policy are different facts and should remain different evidence objects.

```text
peer offers + deterministic selection
        |
        v
authenticated negotiated context (V5)
        |
        v
cryptographic authority lineage
        |
        +---- local NegotiationPolicyV1
        v
authority activation evidence
```

Do not put local policy into V5. V5 is peer-negotiated session state. A local policy is an endpoint decision about whether that authenticated state is acceptable.

Do not omit policy from consequential receipts either. The same authenticated negotiated context may be accepted under a weak minimum policy or a strict allow-list policy, and those are materially different local trust decisions.

## Lineage identity: add an explicit provenance tag

The existing lineage design should include the provenance mode as a domain-separated byte rather than relying on the authority-context hash alone to distinguish pinned legacy from negotiated V2.

Candidate encoding:

```text
lineage_id = SHA-256(
    "xenia.authority-lineage.v1\0" ||
    provenance_tag:u8 ||
    handshake_transcript_hash:[32] ||
    authority_context_hash:[32] ||
    host_identity_fingerprint:[32]
)
```

Provenance tags:

```text
0x00 = PinnedLegacy
0x01 = NegotiatedV2
```

Where:

```text
PinnedLegacy authority_context_hash = pinned_selected_context_hash
NegotiatedV2 authority_context_hash = final_v5_context_hash
```

The explicit tag prevents semantic cross-mode ambiguity even though SHA-256 collision resistance would already make accidental equality negligible.

Frozen synthetic vectors:

```text
transcript_hash = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
authority_context_hash = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
host_identity_fingerprint = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f

PinnedLegacy lineage_id:
e378c3d3f3de8bbf765278840eaee9bc24596ac48e3d7b4064261112fa6860e1

NegotiatedV2 lineage_id:
5dfd523b20912dbe79414515d6812148d7f2f129773a3cae535153a62e4d5015
```

The lineage id remains stable across verified derived rekeys. It changes after a fresh handshake, different authority context, host identity, or provenance mode.

## Local policy identity

`NegotiationPolicyV1` has a separate SHA-256 identity.

Candidate policy modes:

```text
Minimum
  every required exact capability must be selected
  authenticated extras are permitted

AllowList
  every required exact capability must be selected
  every selected exact capability must be explicitly allowed
```

Policy hash domain:

```text
xenia.negotiation-policy.v1\0
```

Frozen examples currently used by native and Wire implementations:

```text
minimum required xenia.causal-authority/draft-04:
6456c40af9e104b82be0b0faf501c404c057d7b55928d339720a9c208f6eef0f

allow-list requiring authority/draft-04 and allowing authority/draft-04 + operator-rekey/v1:
ed37983b2b76cbc7689d80ef2f008bdaf469483bbc2aa1caaed2352992b7fca4
```

A policy hash is local audit evidence. It is not an authorization token and not proof that the remote peer adopted the same policy.

## Activation identity

After an authenticated lineage has been evaluated successfully under a local policy, derive an activation identifier:

```text
activation_id = SHA-256(
    "xenia.authority-activation.v1\0" ||
    lineage_id:[32] ||
    local_policy_hash:[32]
)
```

This gives us three deliberately different questions:

```text
V5 context hash
  what protocol state did both peers authenticate?

lineage_id
  which authenticated session/rekey lineage carries that state?

activation_id
  under which local acceptance policy was authority enabled?
```

Frozen synthetic activation vector using the NegotiatedV2 lineage vector above and the minimum authority policy hash:

```text
activation_id =
a854bec985bd59cedfd4473d93b8fc5e32a043cf635ba7ab77d25a9722e127a7
```

## Policy changes during a live authority session

Do not mutate an active `AuthoritySession` policy in place.

A policy change must either:

1. consume/downgrade the current authority wrapper and re-activate from still-valid authenticated lineage evidence under the new policy; or
2. require a fresh handshake when deployment policy says policy changes are session-bound.

In either case the new policy produces a different `activation_id`.

A weaker policy must never be substituted into an existing receipt chain while retaining the prior activation id.

## Candidate activation evidence

```text
AuthorityActivationEvidenceV1
  lineage_id
  activation_id
  provenance_mode
  handshake_transcript_hash
  authority_context_hash
  selected_context_hash
  negotiation_binding_hash?      # present for NegotiatedV2
  local_policy_hash
  local_policy_mode
  key_epoch
  current_epoch_hash
```

`PinnedLegacy` must never populate fields in a way that implies dynamic two-offer negotiation. Optional fields should be typed by provenance rather than filled with zeroes.

## Receipt binding

A consequential action receipt should bind both:

```text
lineage_id
activation_id
```

plus the already-required exact authority evidence:

```text
authority_id
request_digest
subject_id
target
capability
action_digest
parameters_digest
scope/use policy
key epoch + epoch hash
execution result
evidence digest
```

This lets audit tooling distinguish:

- same session lineage under a different local acceptance policy;
- same V5 context in a completely different handshake lineage;
- pinned legacy authority from dynamically negotiated V2 authority;
- rekey continuation from a fresh handshake.

## Fail-closed rules

- policy evaluation occurs only after negotiation evidence is authenticated;
- local policy is never inferred from peer offers;
- V5 never includes local policy hash;
- lineage identity includes explicit provenance mode;
- activation identity always includes policy hash;
- arbitrary key installation destroys authority wrapper state;
- verified rekey preserves lineage and activation ids while advancing epoch evidence;
- changing local policy changes activation id;
- receipts never render `PinnedLegacy` as `NegotiatedV2`;
- a receipt with the wrong activation id for its policy hash is invalid.

## Adversarial gates before promotion

- same transcript/context/identity but different provenance tag -> different lineage id;
- same lineage with two policy hashes -> different activation ids;
- same V5 context across two handshakes -> different lineage ids;
- policy requires draft-04 but selected draft-03 -> reject before authority activation;
- allow-list mode rejects an authenticated but unreviewed selected extension;
- minimum mode permits authenticated extras while still requiring every exact minimum;
- policy mutation cannot preserve old activation id;
- verified rekey preserves lineage + activation and advances only epoch evidence;
- arbitrary key replacement cannot preserve activation state;
- receipt policy hash / activation id mismatch -> reject.

## Promotion order

1. negotiation semantics + hostile-byte codec green;
2. local policy implementations + independent vectors green;
3. V2 authenticated negotiation green;
4. V5 evidence green;
5. lineage formula with provenance tag implemented and independently vectored;
6. activation evidence implemented and independently vectored;
7. owned AuthoritySession binds lineage + activation state;
8. verified rekey preserves both identities;
9. execution receipts bind lineage + activation + authority_id;
10. crash-safe downstream single-use lifecycle demonstrated;
11. only then make normative draft-04 external-action authority claims.
