# xenia-server + native viewer — plan (draft 1)

**Status**: research + planning complete; **no code written yet**.
Draft for user review before execution starts in a fresh session.

**Scope**: extend Xenia beyond the wire protocol into a real
remote-desktop product: a server that captures a display and
streams it, and a viewer (browser + native) that renders it and
sends input back. This is **Track B** of the Luminous Dynamics
roadmap — product engineering, not protocol research.

**Honesty up front**: a competitive MSP-grade remote-desktop tool
is 9–12 months of focused work for two senior engineers. Solo or
single-platform MVP is weeks to months. This plan deliberately
scopes small-then-grow rather than promising parity with
ConnectWise/Splashtop in one milestone.

---

## 0. What we actually have going in

The Track A sprint already shipped most of the hard parts. Before
any new code, the right mental model is: **80% of the server
already exists in `symthaea/src/swarm/rdp_*.rs` — the work is
extraction + de-Symthaea-ifying, not greenfield.**

### 0.1 Carry wholesale (already production-quality)

| Module | Lines | What it gives us |
|--------|-------|-------------------|
| `rdp_session.rs` | 832 | Full state machine, PQC rekey, grace period, frame ack, backpressure |
| `rdp_protocol.rs` | 462 | Frame/Input/Control types, SessionConfig |
| `pqc_handshake.rs` | 458 | ML-KEM-768 + Ed25519 hybrid, HKDF-SHA256 session key derivation, 13 tests |
| `rdp_server.rs` | 505 | Handle/Actor pattern, 50Hz capture loop, mpsc queueing |
| `quic_transport.rs` | 785 | Iroh QUIC endpoint (server + client modes) |
| `rdp_capture.rs` | 588 | Trait + TestCapture + X11ShmCapture + Wayland stub |
| `rdp_input.rs` | 354 | Trait + Noop/Logging/X11Test/WaylandStub injectors |
| `rdp_clipboard.rs` | 223 | Bidirectional sync with sensitivity scrubbing |
| `rdp_file_transfer.rs` | 198 | Chunked with BLAKE3 verification |
| `rdp_adaptive.rs` | 280 | Quality-adaptation framework (skeleton) |
| `rdp_client.rs` | 466 | FrameBuffer reconstruction, FPS tracking, session state |

That's ~5,150 lines of existing code with a clean architecture.

### 0.2 Drop deliberately

- **`rdp_codec.rs`** (708 lines) — the HDC tile codec is Symthaea's
  research IP. It does content classification + 64×64 tile Hamming
  deltas against a 16,384-dim HDC vector. Beautiful for
  consciousness research; wrong abstraction for a general remote-
  desktop product. Swap for H.264/VP9 via `ffmpeg-next`. We keep
  the `Delta`/`Full` frame *types* and the tile-based encoding
  *structure*; we swap the per-tile encoding from HDC to pixel.
- **Consciousness gating** in `rdp_session.rs` — replace with the
  Xenia-wire consent state machine we already built (SPEC §12).
- **Re-attestation timer** — 60-second "prove your phi is still
  good" check. Again, research thing. Replace with keepalive.
- **Symthaea-core imports** — `rdp_codec` depends on
  `symthaea_core::hdc`; after swap, that dependency dies. No other
  module has similar coupling.

### 0.3 Build fresh

- **WebSocket transport** — not present in the Symthaea stack
  (which standardizes on Iroh QUIC). We need a simpler transport
  for the browser viewer and for environments where Iroh's P2P
  discovery isn't wanted. `tokio-tungstenite` server + browser
  `WebSocket` client is the boring-correct answer.
- **H.264 / VP9 encode/decode** — native server-side encode via
  `ffmpeg-next`; browser-side decode via `WebCodecs` for H.264,
  fallback software path for environments without WebCodecs.
- **Real Wayland capture** — complete the XDG-Portal-Screencast +
  PipeWire path (current Symthaea code stubs this).
- **Real input injection on all three OSes** — `evdev`/`uinput` on
  Linux (with portal+libei for Wayland), `CGEventPost` on macOS,
  `SendInput` on Windows. `enigo` is a credible cross-platform
  starting point but has known Wayland gaps; wrap per-platform.
- **Cursor sync** — not in Symthaea yet. Remote cursor shape +
  position delivered out-of-band from frames.
- **Multi-monitor** — placeholder methods exist in the capture
  trait; no actual implementation.
- **Browser viewer that's a real viewer** — the current
  `xenia-viewer-web` is demo-quality. A real viewer needs
  WebCodecs H.264 decode, WebGL render, IME-aware keyboard
  capture, pointer-event fidelity, audio via WebAudio, clipboard
  via `navigator.clipboard`.

---

## 1. Crate and repo layout (proposed)

```
Luminous-Dynamics/
├── xenia-wire              # already exists — the wire protocol
├── xenia-server            # NEW — this plan's target
│   ├── crates/
│   │   ├── xenia-server            # the binary
│   │   ├── xenia-server-core       # transport + session (ex-Symthaea extraction)
│   │   ├── xenia-capture           # screen capture abstraction + backends
│   │   ├── xenia-inject            # input injection abstraction + backends
│   │   ├── xenia-video             # codec wrapper (ffmpeg-next)
│   │   └── xenia-transport-ws      # WebSocket variant (QUIC comes from -core)
│   └── ...
└── xenia-viewer-native     # NEW — native GUI client (eventual)
    ├── src/                # egui or Tauri, TBD
    └── ...
```

**Rationale**:

- Separate repo from `xenia-wire` because the server has a
  materially larger dependency surface (`ffmpeg-next`, `x11rb`,
  `wayland-*`, `windows-rs`, `objc2-*`) that would taint the
  small, clean `xenia-wire` crate's ecosystem footprint.
- Split into sub-crates inside `xenia-server` so `xenia-capture`
  and `xenia-inject` can be reused by other viewers and so
  platform-specific build failures don't cascade.
- `xenia-viewer-native` is a separate repo because it targets
  end-user desktops and may eventually be closed-source or
  dual-licensed — don't bleed that discussion into the
  protocol/server repos.

**Licensing**: inherit Apache-2.0 / MIT dual for server. Native
viewer license is an open decision (see §6 open questions) — NOT
defaulted in this plan.

---

## 2. Architecture

### 2.1 Data path, forward

```
┌─────────────────┐  ┌─────────────────────────────────────────────────────┐
│  target screen  │→ │ xenia-capture → xenia-video.encode → xenia-wire::Frame│
│  (X11/Wayland/  │  │      │                                   │           │
│   Windows/Mac)  │  │    RGBA                             Frame { id, ts,  │
└─────────────────┘  │    frames                            payload: H.264 }│
                     │      │                                   │           │
                     │      ▼                                   ▼           │
                     │ delta detect                    xenia-wire::seal →   │
                     │  (optional)                     transport (QUIC/WS)  │
                     └─────────────────────────────────────────────────────┘
                                                                 │
                                                                 ▼
                                                  ┌──────────────────────┐
                                                  │     Viewer side      │
                                                  │ transport.recv →     │
                                                  │ xenia-wire::open →   │
                                                  │ xenia-video.decode → │
                                                  │ render to canvas/    │
                                                  │         WebGL        │
                                                  └──────────────────────┘
```

### 2.2 Data path, reverse (input)

```
┌──────────────────┐   ┌─────────────────────────────────────────────┐
│  viewer UI       │ → │ capture keyboard/mouse/touch →              │
│  (browser/       │   │   serialize as InputEvent →                 │
│   native egui)   │   │   xenia-wire::seal_input → transport.send   │
└──────────────────┘   └─────────────────────────────────────────────┘
                                                    │
                                                    ▼
                        ┌───────────────────────────────────────────┐
                        │  Server side                              │
                        │  transport.recv → xenia-wire::open_input  │
                        │    → xenia-inject.inject_*                │
                        │    (gated on ConsentState == Approved)    │
                        └───────────────────────────────────────────┘
```

### 2.3 Control plane

Consent ceremony messages (`0x20`/`0x21`/`0x22`), keepalive,
handshake rekey, session close — all flow on the same transport as
a separate payload-type stream, replay-protected independently per
the `(source_id, payload_type)` window xenia-wire already
provides.

### 2.4 Why two transports

- **QUIC** (Iroh) — primary production transport. Loss-resilient,
  stream multiplexed, 1-RTT handshake. Best experience on any
  lossy link (cellular, Wi-Fi). The WebSocket-over-QUIC head-of-
  line blocking study we cite in `papers/xenia-paper.md` §5.4 is
  why we want this as default.
- **WebSocket** — browser compatibility + environments that can't
  open UDP (corporate NATs with strict egress, CI/CD, school
  networks, carrier-grade NAT). Acceptable quality on wired / low-
  loss links; noticeably worse than QUIC under 1%+ packet loss.

Both transports ship sealed `xenia-wire` envelopes. The wire
format is transport-agnostic by design.

---

## 3. Milestones

Each milestone has an **exit criterion** — a single demonstrable
thing that's true once the milestone is done. No fuzzy "ready for
review" — pick something binary.

### M0 — Extract + de-Symthaea-ify (1–2 weeks)

**Scope**: create `Luminous-Dynamics/xenia-server` repo. Copy the
11 files from §0.1 into `crates/xenia-server-core/`. Swap
`rdp_codec.rs` (HDC) for a stub codec that passes RGBA bytes
through unchanged (no compression). Strip consciousness gating
from `rdp_session.rs`; replace with `xenia-wire` consent state.
Drop the `symthaea_core` import entirely.

**Exit criterion**: `cargo test -p xenia-server-core` green, and
a `RawServer`/`RawViewer` integration test exchanges 100 RGBA
frames through the sealed wire over QUIC on localhost.

**Non-goals**: performance, compression, real capture.

### M1 — Real capture + video encode on Linux (2–3 weeks)

**Scope**: complete `xenia-capture` with an X11 backend (finish
the X11ShmCapture that's already stubbed) and a Wayland backend
(XDG-Portal-Screencast + PipeWire, with DMA-BUF mapping for zero-
copy). Build `xenia-video` around `ffmpeg-next` for H.264 hardware
encode (VAAPI on Linux). Viewer side: add WebCodecs H.264 decode
to `xenia-viewer-web` with a WebGL2 renderer.

**Exit criterion**: server captures the user's Linux desktop at
1080p and the browser viewer renders it at ≥ 20 fps on a
workstation + Pixel 8 Pro test pair over USB tether. HEVC is
nice-to-have but H.264 is the exit bar.

**Non-goals**: input injection, macOS, Windows, multi-monitor,
cursor sync, clipboard, audio, unattended access.

### M2 — Input injection + consent flow (1–2 weeks)

**Scope**: complete `xenia-inject` with a Linux X11 backend
(x11rb XTest — real, not stubbed) and a Wayland backend (libei +
xdg-portal RemoteDesktop — with the expected user-consent prompt
on session start). Wire the consent ceremony from SPEC §12 so that
(a) server refuses to accept input until `ConsentState =
Approved`, (b) the viewer shows the ceremony UI on connect, (c)
revocation terminates input forwarding within one frame budget.

**Exit criterion**: end-to-end demo where user at viewer clicks
on the canvas, the click is injected into the server's X session,
and the resulting cursor movement is visible in the next captured
frame. Revocation click stops input injection immediately.

**Non-goals**: macOS/Windows input injection, cursor *shape* sync,
clipboard, file transfer.

### M3 — Cross-platform (4–6 weeks)

**Scope**: implement `xenia-capture` and `xenia-inject` backends
for macOS (ScreenCaptureKit + CGEventPost) and Windows
(Windows.Graphics.Capture + SendInput). VideoToolbox hardware
encode on macOS; Media Foundation or NVENC/AMF on Windows.
Installer signing (Authenticode, notarization) pushed to M4 —
M3 is running-from-cargo-run only.

**Exit criterion**: three separate video demos — Linux → browser,
macOS → browser, Windows → browser — each achieving ≥ 20 fps
1080p with hardware encode.

**Non-goals**: unattended access, audit logging, MSP console.

### M4 — Productization (3–4 months)

**Scope**: everything that takes a demo to a product.

- Native viewer — `xenia-viewer-native` via egui or Tauri.
- Cursor shape sync.
- Multi-monitor (capture selection, viewer routing).
- Clipboard — extract `rdp_clipboard.rs`, wire to system clipboard
  via `xsel`/`wl-copy`/`pbcopy`/`Windows.ApplicationModel.DataTransfer`.
- File transfer — extract `rdp_file_transfer.rs`, wire UI.
- Audio — extract `rdp_audio.rs` traits; implement ALSA/Pulse,
  CoreAudio, WASAPI backends.
- Unattended access — server starts as service, auto-launches on
  boot, accepts connections against pre-approved ID+PIN+key.
- Audit log — extract the attestation chain (SPEC §12 `0x23`
  reserved) for every action the technician takes.
- Session recording — extract the `.xenia-session` sealed-replay
  format.
- Reconnect + session resume.
- Rate adaptation — flesh out `rdp_adaptive.rs`.
- Installer packaging + signing.
- Configuration UI + CLI.

**Exit criterion**: a paying MSP could install the server on 5
client endpoints, the viewer on their technician's workstation,
and actually use it for a workday. Not: feature parity with
ConnectWise. Just: doesn't fall over.

### M5+ — Competitive (beyond 12 months)

At this point we're in real-product territory and the roadmap is
signal-driven. Likely candidates:

- Support-code (attended) flow with a 6-digit one-time ID.
- MSP admin console (Track C).
- PSA integrations (Autotask, ConnectWise Manage, HaloPSA).
- Mobile viewer (iOS/Android).
- Self-hosted relay with federation.
- Compliance paper trail (HIPAA, SOC 2 log requirements).

These are product-company-scale bets. Each is its own go/no-go.

---

## 4. Technology choices + rationale

Decisions I'm pre-committing to in this plan because they should
not be re-litigated per milestone. Each can be overridden by the
user with a short written rationale.

### 4.1 Video codec: H.264 (primary), VP9 (fallback), HEVC (bonus)

- H.264 has hardware encode on every production CPU/GPU in the
  last decade and browser decode everywhere.
- VP9 is universally supported in WebCodecs and handles software
  decode well for environments without H.264 hardware.
- HEVC is nice for bandwidth-constrained links but adds licensing
  complexity; only include if hardware encode is present.
- **Not** AV1 — `rav1e` can't sustain real-time interactive above
  720p; SVT-AV1 is C (fine to depend on via ffmpeg-next later, but
  not the primary).

### 4.2 Encode/decode wrapper: `ffmpeg-next`

- Mature, handles all 4 codec × 4 hardware-accel-backend
  combinations.
- Known heavy build dependency (libclang, glibc headers) — same
  footprint Symthaea's `symthaea-phone-embodiment` already accepts.
- RustDesk's `hwcodec` is a reference implementation of this
  pattern — we don't copy their code, but we adopt their approach.

### 4.3 Capture: per-platform crates behind the `xenia-capture` trait

- **Linux X11**: finish `x11rb`-based MIT-SHM (already stubbed).
- **Linux Wayland**: `lamco-pipewire` + `lamco-portal` (battle-
  tested in 2026, DMA-BUF zero-copy). Accept that the portal
  consent prompt is non-suppressible — that's the design.
- **macOS**: `screencapturekit` crate (1.5.4+, actively
  maintained).
- **Windows**: `windows-capture` crate (modern WGC API).
- **Do not** use `scap` cross-platform crate as a hard dependency —
  too new to bet on for a multi-year product. Read it for ideas.

### 4.4 Input injection: per-platform behind `xenia-inject` trait

- **Linux X11**: `x11rb` XTest — complete the stub.
- **Linux Wayland**: libei via `reis-rs` (when the compositor
  supports it) + xdg-portal RemoteDesktop (when it doesn't).
- **macOS**: `core-graphics` crate's `CGEventPost`. Accessibility
  permission prompt on first launch.
- **Windows**: `windows-rs` `SendInput`. UIPI elevation parity
  required for UAC windows.
- **Do not** depend on `enigo` as the production cross-platform
  abstraction — its Wayland support is explicitly experimental and
  its text-entry path is buggy. Read it for ideas.

### 4.5 Transports: Iroh QUIC (primary) + tokio-tungstenite WS (fallback)

- Iroh gives us P2P NAT traversal + DERP relay for free, which is
  the ConnectWise-killer feature architecturally.
- WebSocket is the boring-correct browser fallback.
- Both terminate the same sealed envelope format; the transport is
  ignorant of what it carries.
- **Do not** roll our own KCP-style reliable-UDP (RustDesk's path)
  — it's re-inventing QUIC poorly.

### 4.6 Browser viewer: WebCodecs + WebGL2

- Raw Canvas 2D for `putImageData` at 1080p is CPU-bound and loses
  to WebGL by ~1.7×. For a product viewer, WebGL2 is table stakes.
- WebCodecs for H.264 decode is supported on Chrome/Edge/Firefox
  (desktop + Android, except Firefox Android); Safari covers HEVC
  natively. Good enough.
- WebGPU is not yet required — revisit at M5 if latency demands it.

### 4.7 Native viewer: egui (MVP) → Tauri (product)

- egui gives us fast iteration on the existing `rdp_render_egui.rs`.
- Tauri is where we'll end up for a shipping product (native look,
  installer story, auto-update infrastructure).
- **Do not** go Electron — the 200 MB base weight is unserious
  next to Rust-native options.

### 4.8 Handshake: extract `pqc_handshake.rs` as-is

- ML-KEM-768 + Ed25519 hybrid is production-quality and already
  tested in Symthaea. Carry it into `xenia-server-core` with no
  changes except the zeroization path.
- **Do not** re-derive — this is exactly the kind of code that
  should not be re-invented.

---

## 5. Risks + open questions

### 5.1 Wayland consent prompt (design-level)

Every Wayland capture session triggers an `xdg-desktop-portal`
consent dialog. Every input injection session, same. This is
non-suppressible and by design. **For unattended-access use cases
(the MSP default), this is a deal-breaker on Wayland.** Three
mitigation paths:

- (a) Fall back to X11 on Linux for unattended-access mode.
- (b) Use `libei` exclusively on wlroots compositors (Sway,
  Hyprland) which allow broader programmatic input, at the cost of
  GNOME/KDE Wayland coverage.
- (c) Accept the limitation and target X11-only Linux servers for
  unattended access until Wayland standardizes.

**This decision affects M2 and M4 heavily.** Getting it wrong
early costs weeks of re-work.

### 5.2 Hardware encode licensing

H.264 hardware encoders on some platforms (notably consumer NVIDIA
GeForce) have 3–5 concurrent session caps. For a multi-tenant MSP
server that's a problem. RustDesk hit this wall. For the MVP it's
fine; for V1 we need to detect and degrade gracefully (software
fallback or deny new session).

### 5.3 The honesty gap vs. the plan's original 2-3 week framing

In this session we told the user #2 (full viewer) was "2-3 weeks
of real engineering." The landscape research returns 9–12 months
for product-grade MVP with two engineers. **This plan's estimate
is closer to the landscape's**: M0+M1+M2+M3 adds to roughly 2–4
months of focused work even with the 80% head start. Anything
approaching Splashtop feel is months more.

This is worth re-confirming with the user before committing.

### 5.4 The HDC codec question

Deleting `rdp_codec.rs`'s HDC layer removes Symthaea's
content-classification + consciousness-gated quality adaptation.
For a general MSP tool this is the right call. For a future
research use (observing what content technicians are viewing,
privacy masking per the paper's §7.4) it matters. A resolution:

- Keep `rdp_codec.rs` in Symthaea's tree unchanged (already there).
- `xenia-server` uses standard video codecs only.
- Future `xenia-research-bridge` crate (if warranted) can plug
  Symthaea's HDC codec in behind a feature flag.

This keeps the research substrate and the product cleanly
separated.

### 5.5 Signal-dependent scope

Per the Track A FOLLOW_UPS.md, Track B viability is gated on
evidence that Track A generated inbound interest. We're now
considering starting Track B before any Track A signals. Two
framings:

- **"Build it and they will come"** — the demo is the best
  recruiting tool, we can't wait.
- **"Evidence before investment"** — spending 2–4 months on a
  product when nobody has asked is speculative.

The plan pretends neither framing is obviously correct. Milestone
M0 is cheap enough (1–2 weeks) that it generates concrete
deliverables usable in outreach even if we don't go past it.

### 5.6 License question for native viewer

`xenia-server` clearly should match `xenia-wire` at Apache/MIT.
`xenia-viewer-native`'s license is less obvious — if Track B/C
commercial licensing ever happens (see FOLLOW_UPS.md), the native
client is the natural entry point. Leaving it Apache/MIT means
any competitor can take the whole stack; choosing AGPL or a
source-available model is a real option. **This deserves its own
decision before M4**, not an automatic carry-forward.

### 5.7 Repository management overhead

Splitting into 3+ repos means 3+ CI pipelines, 3+ release cycles,
3+ issue trackers. Each saves a design problem but costs an ops
problem. A monorepo with sub-crates under `xenia-server/` is the
cheapest alternative. I've proposed the split because of the
dependency-footprint reasoning in §1; an honest counter-argument
is "just use one repo with good feature flags."

---

## 6. Decisions needed before M0 starts

These block the first line of code:

1. **Repo structure**: new `xenia-server` repo, or embed as a
   top-level subcrate in a `xenia-platform` monorepo, or carry
   it as `xenia-server/` inside `xenia-wire` for now?
2. **License posture**: Apache/MIT for the server assumed; confirm.
3. **Wayland policy** (§5.1): X11-only for unattended,
   portal-prompted for attended, or libei-only on wlroots?
4. **Time commitment**: M0 (1–2 weeks) as a first bite, or commit
   to M0+M1+M2 as a ~6-week sprint?
5. **Signal-gating**: start M0 now regardless of Track A signal,
   or wait for first cryptographer review / first MSP contact?

Each is a user decision. None should be decided by the engineering
side.

---

## 7. What `xenia-server` is deliberately NOT

Captured here so scope creep has something to bounce off:

- **Not a SaaS**. The server is self-hosted (MSP runs their own).
  Hosted tenant platform is Track C.
- **Not a ticketing tool**. Integrates with PSA (Zammad, HaloPSA,
  ConnectWise Manage) as an external system.
- **Not a patch-management / RMM / endpoint-management tool**.
  That's Tactical RMM / Meraki / Intune territory.
- **Not a password manager / identity provider**. Integrates with
  external IdP (OIDC, SAML eventually).
- **Not a VPN**. The wire provides confidentiality + integrity;
  does not pretend to provide network reachability.
- **Not a mobile remote-control**. Viewing your workstation from a
  tablet is a minor case; controlling a phone is RustDesk's lane.
- **Not a game-streaming tool**. The encoder profile is tuned for
  desktop workloads, not 4K60 HDR gaming. Go use Moonlight.

---

## 8. Parallel recommendation: keep Week-6 outreach running

The BLOG_POST_1, BLOG_POST_2, and FOLLOW_UPS work from Week 6 is
orthogonal to this plan. The user's outreach decisions should
continue regardless — even M0's deliverables (a minimal Linux-to-
browser raw-RGBA viewer over Xenia) are more persuasive in the
MSP outreach than the current WASM demo. **Do outreach in
parallel with M0**; the two feed each other.

---

## Appendix A. Prior art consulted

Full landscape research is in
`plans/research/VIEWER_RESEARCH.md` (separate file; includes
RustDesk architecture notes, Guacamole lessons, screen-capture
library comparison, encoding-stack tradeoffs, input-injection
platform matrix, and browser-viewer performance analysis).

---

## Appendix B. Open for iteration

This is draft 1. Expected to go through at least one revision
before M0 starts. Revisions tracked at the head of this file.

*— plan authored 2026-04-18 after Track A close. Not committed
to crates.io or product-company infrastructure. Start with §6.*
