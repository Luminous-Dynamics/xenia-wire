# Authority session rekey boundary

This note records a staging invariant for the causal-authority draft stack.

`xenia_wire::Session` is a single-AEAD-key envelope session. Its compatible long-lived rekey protocol is the operator-channel rekey domain (`xenia-operator-rekey-epoch-context-v1`).

The native xenia-peer multi-lane session uses a distinct lane/session rekey domain (`xenia-rekey-epoch-context-v1`) and must own its own authority-session wrapper when live V2 integration reaches that layer.

Therefore the Wire-owned `NegotiatedAuthoritySession` must not apply `LaneSessionV1` evidence to its single raw AEAD key. A mathematically valid lane epoch hash is not permission to reinterpret a single-key envelope session as a multi-lane session.

Target invariant:

```text
xenia-wire Session
    -> OperatorChannelV1 only

xenia-peer multi-lane session
    -> LaneSessionV1 only
```

This is a staging/design note, not a normative SPEC claim. The code-level enforcement is tracked in the stacked successor to xenia-wire #27.
