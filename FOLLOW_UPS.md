# Follow-ups

Gated options that Xenia might pursue after Track A. **Track B/C are
not committed** — they are a feedback-gated option. What to do next
depends on which signals come back from the Track A launch.

This file is the living record of "if this signal arrives, we
consider doing X." Entries are added as signals surface; entries are
removed as they're closed (done, rejected, superseded).

## Signal → action mapping

### If the paper is accepted at a Tier-1 security venue

- Write a follow-up paper on the consent-ceremony semantics
  (separate publication, different venue).
- Commission a formal EasyCrypt proof of the AEAD composition
  (grad-student-semester-scale; check OpenSSF / Sovereign Tech Fund
  grant availability first).
- Propose the consent-ceremony specification as an IETF informational
  RFC through the CFRG working group.

### If crates.io downloads exceed 1,000 in the first quarter

- Bump to `0.2.0` with a fully frozen wire format.
- Add a reference implementation in at least one additional language
  (Go likely, given the MSP-adjacent ecosystem).
- Write a `xenia-conformance` test harness that an alternate-
  language implementation can run against the published test
  vectors.

### If existing OSS MSP tools express adoption interest

- Specifically for **Tactical RMM, MeshCentral, or RustDesk**:
  offer a compatibility-patch PR rather than asking them to replace
  their wire. The goal is interop, not displacement.
- Write a migration guide: "your current AES-GCM wire → Xenia's
  ChaCha20-Poly1305 wire, preserving existing session semantics."
- Spin up a shared issue tracker or weekly sync for protocol
  evolution.

### If three or more MSP practitioners reach out from BLOG_POST_2

- Hold 20-minute architecture calls with each.
- **Listen more than pitch.** The goal is to understand threat model
  mismatches, not to sell.
- Aggregate the findings into a "MSP reality check" doc —
  publish-ready if the signal is strong, private-notes if the
  findings are specific enough to identify individual operators.

### If Track B (Windows/macOS agents) becomes viable

Gating condition: two of (paper accepted, crate adoption
>100 GitHub stars, >1000 downloads, MSP-practitioner validation).

- Scope gate: Windows agent first, not macOS. Windows is 85% of the
  MSP endpoint population.
- Absolutely no iOS agent in Track B — App Store review dynamics
  make it a poor first-mover platform for a pre-alpha protocol.
- Design principle: the agent is a thin client; all policy lives
  server-side in the existing Track B/C architecture.

### If Track C (MSP tenant platform) becomes viable

Gating condition: Track B has shipped a Windows agent AND three or
more MSPs have run it in production with positive signal.

- Build on Holochain for the trust topology. The authors'
  organization already runs Holochain infrastructure; this is the
  lowest-friction path.
- Explicitly avoid re-inventing the MSP tooling ecosystem. The goal
  is a *trust topology* replacement, not a *tooling* replacement —
  leave ticketing (Zammad/HaloPSA/etc.), endpoint management
  (Meraki/Intune/etc.), and billing (Kaseya BMS/ConnectWise PSA)
  alone.

### If nothing sticks

- Track A's outputs (crate, spec, paper, demo) stand on their own
  merits. The crate remains open-source; the spec remains the
  normative reference; the paper goes to arxiv regardless.
- The research program (Phase III / Phase IV in the parent
  Symthaea roadmap) benefits from the cleaner extracted crate.
- **No pressure to continue.** Commercially-null does not mean
  research-null. Move on.

## Inventory of open spec extensions

Not part of Track A. Documented in the paper's §7 and here for
completeness. Each entry has an estimated complexity + blocking
dependency.

### v1.1 — Ricardian causal-binding on ConsentRequest

- **Placeholder**: `causal_binding: Option<CausalPredicate>` field
  already in the draft-03 wire format (MUST be `None` in draft-03).
- **What**: authority binding ("valid while ticket #1234 is
  In-Progress") evaluated against an external truth source.
- **Blocker**: decentralized-identity layer on Holochain must have
  a queryable state graph.
- **Complexity**: 2-3 focused weeks once blocker is resolved.

### v1.1 — AttestedAction payload (0x23)

- **Placeholder**: payload type reserved in registry.
- **What**: monotonic hash-chain of technician commands.
- **Blocker**: none. Implementation could start immediately.
- **Complexity**: 1 focused week.

### v1.1 — Sealed-replay recording format (.xenia-session)

- **Placeholder**: none on the wire — this is a file format.
- **What**: tamper-evident recording of a full session as a series
  of sealed envelopes with a metadata header.
- **Blocker**: none.
- **Complexity**: 1-2 focused weeks.

### v1.2 — MSP attestation chain

- **Placeholder**: SPEC §12.5 notes `msp_attestation` as a future
  field on `ConsentRequest`.
- **What**: MSP's Holochain agent key signs the technician's device
  key. End-user's client queries the Holochain DHT to verify.
- **Blocker**: Holochain DHT directory schema (ongoing design work
  in the parent organization).
- **Complexity**: 2 weeks for the field + spec language; months for
  the full directory infrastructure.

### v2 — Privacy masking via Symthaea

- **What**: on-device consciousness-gated observation of outbound
  frames; tiles containing sensitive content (passwords, medical
  records, banking fields) are masked server-side before sealing.
- **Blocker**: Symthaea public API (`symthaea-vision` crate) must
  ship. Currently an internal research substrate.
- **Complexity**: infrastructure-level. Separate Track.
- **Research note**: the paper's §7.4 flags this as the "most
  distinctive contribution of the program" if it ships.

### v2 — Biometric proof-of-presence

- **What**: periodic device-signed liveness attestations ensure the
  person holding the tech session is the same person who signed in.
- **Blocker**: user-research with accessibility advocates + MSP
  technicians to pick modalities that don't discriminate.
- **Complexity**: requires policy design as much as code.

### Speculative — Holographic replay audit

- **What**: 3D/VR rendering of a session replay for compliance
  auditors.
- **Blocker**: usability-research evidence that the 3D view actually
  helps auditors. Without that, this is research-curious, not
  product-urgent.
- **Complexity**: companion product, not a spec extension. Lives as
  a potential `xenia-audit-studio` if it ever ships.

## Decisions being deferred

### When to bump to 0.2.0 stable

**Updated 2026-04-18 (post-Phase-B).** The 0.1.0 target became a
0.2.0 target once draft-03 added mandatory `session_fingerprint` (a
breaking wire change at the signed-consent-body layer). Published
state: `0.2.0-alpha.2`, SPEC draft-03, all four round-2 review
issues closed.

**Current policy**: stay at `0.2.0-alpha.x` until a round-3
independent cryptographer review signs off on the draft-03-specific
additions — specifically SPEC §12.3.1 (session_fingerprint HKDF
construction), §12.6.1 (normative transition table), and §12.8
(timing-channel assumption). A scoped delta doc for the reviewer
is at `plans/REVIEW_DELTA_DRAFT_03.md`. If review finds issues,
iterate alpha.3+. If review is clean, bump to `0.2.0-rc.1`.

### Whether to host a live demo

The `xenia-viewer-web` crate builds cleanly. Hosting the demo
requires a DNS decision (`xenia.luminousdynamics.io`? somewhere on
`mycelix.net`?) and a choice of static host. Deferred until there's
external interest to justify the infra cost (Cloudflare Pages is
free; the deferred cost is operational attention, not dollars).

### Paper venue

Originally targeted USENIX Security, NDSS, CCS, or S&P 2027. Final
choice pending CFP alignment and informal-review feedback. If the
paper returns from review with substantive changes needed, a
workshop-track submission may be more appropriate than a top-tier
main track.

## Closed items

- **Round-2 review issues #1-#4** (2026-04-18). All four items
  flagged by the round-2 cryptographic review are now closed. #2
  split `Pending` + #4 configurable replay window shipped as
  `0.1.0-alpha.5` (SPEC draft-02r2, receiver-local). #1 mandatory
  `session_fingerprint` + #3 normative transition table shipped as
  `0.2.0-alpha.1` (SPEC draft-03, breaking at the signed-body
  layer). Receiver hardening (rekey-aware verify, timing-channel
  note, violation vectors, fuzz harness, MIGRATION.md) shipped as
  `0.2.0-alpha.2`.
- **Per-key-epoch replay bug** (#5) (2026-04-18). Closed in
  `0.1.0-alpha.4`. `ReplayWindow` keyed by `(source_id, pld_type,
  key_epoch)` per SPEC §5.3.

---

*This file is maintained in the repo so Track A readers can see what
comes next without needing access to internal planning docs.*
