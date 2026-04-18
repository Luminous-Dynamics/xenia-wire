# Viewer research — raw findings

Research dump backing `plans/VIEWER_PLAN.md`. Kept verbatim as the
evidence record so the plan's recommendations stay auditable.
Consolidated from two agent investigations run 2026-04-18.

## 1. Symthaea RDP stack inventory

### 1.1 Production-quality modules (extractable as-is)

- `rdp_server.rs` (505 LOC) — Handle/Actor pattern for 50Hz frame
  producer. Manages session lifecycle, receives screen frames,
  queues to clients via mpsc. No feature gate. Depends tokio +
  serde_json. **Production.**
- `rdp_session.rs` (832 LOC) — State machine
  (Connecting→Handshaking→Authenticating→Active⇄ViewOnly/Rekeying→
  Closing). PQC key rotation, consciousness re-attestation (60s),
  frame acking. Max 8 sessions. Behind `mesh-encryption`. Depends
  serde + tokio. **Production.**
- `rdp_protocol.rs` (462 LOC) — Frame types (Full, Delta, Input,
  Control, Audio); ControlMessage enum (Hello, Welcome,
  RequestFullFrame, FrameAck, Goodbye, ConsciousnessAttestation,
  ClipboardUpdate); InputEvent (Pointer, Key, Touch);
  RdpSessionConfig. No gate. Depends serde. **Production.**
- `pqc_handshake.rs` (458 LOC) — ML-KEM-768 encapsulation +
  Ed25519 classical handshake. Derives 32-byte session key via
  HKDF-SHA256(classical_nonce \|\| kem_shared). Behind
  `pqc-handshake`. Depends mycelix_crypto + blake3. 13 tests.
  **Production.**
- `quic_transport.rs` (785 LOC) — Iroh QUIC endpoint (server/client
  modes). Handles connection accept loop, bidirectional streams,
  frame serialization/deserialization. Stub when `swarm` disabled.
  Behind `swarm`. Depends iroh + tokio. **Production.**
- `rdp_transport.rs` (447 LOC) — Iroh QUIC transport abstraction.
  Handle/Actor split. Stream multiplexing (STREAM_CONTROL=0,
  STREAM_VIDEO=1, STREAM_INPUT=2, STREAM_AUDIO=3, STREAM_FILE=4,
  STREAM_CHAT_EXEC=5). Behind `swarm`. Depends iroh + tokio.
  **Production.**
- `rdp_codec.rs` (708 LOC) — Hybrid HDC+pixel codec. 64×64 tile
  grid, per-tile Hamming distance delta detection (~65μs/frame).
  Content classification (Static/Text/Photo/Video). TILE_SIZE=64,
  TILE_HDC_DIM=16384. No gate. Depends symthaea_core::hdc.
  **Production.** — **but Symthaea-specific. Plan drops this.**
- `rdp_capture.rs` (588 LOC) — Trait-based screen capture:
  TestCapture (always available), BlankCapture, X11ShmCapture
  (behind `rdp-x11`), WaylandCapture (behind `rdp-wayland`).
  Auto-detection fallback. RGBA output. Depends x11rb +
  zbus/pipewire (stubs work). **Production + Stubs.**
- `rdp_input.rs` (354 LOC) — Input injection trait:
  `inject_pointer()`, `inject_key()`, `inject_touch()` (normalized
  0.0–1.0). Implementations: NoopInjector, LoggingInjector,
  X11TestInjector, WaylandVirtualInput (stub). No gate. Depends
  evdev + x11rb (opt). **Stubs + Interfaces.**
- `rdp_client.rs` (466 LOC) — Client handle: FrameBuffer
  reconstruction, delta/full frame application, FPS tracking,
  input batching. Session state tracking. No gate. Depends tokio.
  **Production.**
- `rdp_render_egui.rs` (275 LOC) — egui-based renderer: GPU
  texture upload, pointer/keyboard capture, status overlay
  (consciousness level, FPS, state). Behind `gui`. Depends eframe
  + egui. **Production.**

### 1.2 Extended feature modules

Production-quality and worth carrying forward:

- `rdp_clipboard.rs` (223 LOC) — Bidirectional clipboard sync with
  dedup, 10MB size limit, sensitivity scrubbing (redacts API keys,
  passwords). Consciousness-gated.
- `rdp_file_transfer.rs` (198 LOC) — Chunked 64KB with BLAKE3
  verification. Offer/Accept/Reject protocol.
- `rdp_adaptive.rs` (280 LOC) — Quality adaptation framework: FPS,
  tile threshold, codec parameters based on network/peer
  consciousness. Skeleton only.

Experimental / skeleton:

- `rdp_audio.rs` (285+ LOC) — Audio capture trait + consciousness-
  gated quality. Stub sine wave + silent sources.
- `rdp_recording.rs` (321 LOC) — Session recording skeleton.
- `rdp_governance.rs` (253 LOC) — Rate limiting + ACL skeleton.
- `rdp_behavioral_auth.rs` (444 LOC) — Keystroke + pointer
  biometrics (research-grade).
- `rdp_remote_exec.rs` (458 LOC) — Shell exec skeleton.
- `rdp_support_bridge.rs` (401 LOC) — Read-only tech support
  skeleton.
- `rdp_unattended.rs` (324 LOC) — Unattended RDP skeleton.
- `rdp_protocol_ext.rs` (100 LOC) — Protocol extension
  declarations.
- `rdp_holon_bridge.rs` (414 LOC) — Holochain DHT integration stub.

### 1.3 Notable absences in Symthaea stack

- **No WebSocket transport** — only QUIC via Iroh. Must build
  fresh for browser viewer.
- **No cursor sync** — cursor shape + position not currently
  synced out-of-band from frames.
- **No multi-monitor** — placeholder methods exist
  (`enumerate_monitors()`, `select_monitor()`) but no
  implementation.
- **No real Wayland capture** — stub only. PipeWire integration
  with DMA-BUF mapping remains TODO.
- **No real X11 input injection** — XTest calls currently log
  only, no real injection.
- **No real Wayland input injection** — WaylandVirtualInput is
  placeholder for wlr-virtual-pointer; no libei integration.
- **No clipboard system integration** — clipboard module exists
  but not wired to xsel / wl-copy / system pasteboard.

### 1.4 Performance targets documented in Symthaea code

- X11 SHM capture: <5ms per 1080p.
- Wayland PipeWire capture: <10ms per 1080p.
- Both fit within 50Hz tick budget (20ms).
- HDC tile Hamming delta: ~65μs per frame at 64×64 tiles.

## 2. RustDesk architecture (comparable)

- **Screen capture**: Per-platform `libs/scrap`. Windows Desktop
  Duplication API. macOS migrating to ScreenCaptureKit. Linux X11
  via xcap-style paths. Linux Wayland weak (issue #10300 indicates
  portal-based + fragile). Android MediaProjection via JNI.
- **Codec**: Multi-codec negotiation — VP8, VP9, AV1 (software),
  H.264/H.265 (hardware-only, via `hwcodec` FFmpeg wrapper). Two
  hardware paths: HWRAM (system-memory buffers covering NVENC/
  QSV/AMF/VAAPI/VideoToolbox) and VRAM (direct GPU texture
  encode). `VideoQoS` struct dynamically tunes spf + bitrate.
  Discussion #8828: pure-software H.264 intentionally absent;
  falls back to VP9 if no H.264 hardware.
- **Transport**: Unified `Stream` over TCP + WebSocket + KCP
  (reliable-UDP ARQ protocol, NOT QUIC). Length-delimited codec.
  NAT traversal: UDP hole punching → IPv6 direct → relay (hbbr).
  Rendezvous server (hbbs) default port 21116/UDP.
- **AGPL avoidance (for clean-room)**: `libs/scrap`,
  `libs/hbb_common`, `src/rendezvous_mediator.rs`, hbbs/hbbr
  source, H.264/H.265 frame-packing logic, .proto signaling
  definitions. BetterDesk (Go) is existence proof that clean-room
  reimplementation of the protocol from published specs is safe.
- **Scaling ceilings**: hbbr hits UDP buffer + FD limits
  (`LimitNOFILE=1000000` config hint). NVENC concurrent-session
  limits on consumer NVIDIA drivers (max 3–5 on GeForce; unlimited
  on Quadro/datacenter — discussion #11144). Community reports
  ~50 concurrent users per relay before degradation.

## 3. Apache Guacamole lessons

- **Architecture**: Server-side `guacd` daemon translates
  VNC/RDP/SSH into a text-based Guacamole protocol streamed over
  WebSocket to browser HTML5 client. JS client renders to
  `<canvas>`. Critical: client doesn't speak VNC or RDP — only
  speaks Guacamole protocol.
- **Canvas rendering**: Vector primitives (Cairo-like: `rect`,
  `line`, `arc`, `cfill`, `cstroke`, `transfer`) + bitmap streams
  (`img` instruction with PNG/JPEG/WebP sub-streams). Multi-layer
  compositing, integer layer IDs, offscreen buffers, tiled
  patterns. NOT "decode video frame, blit" — it's a compositing
  display list.
- **Latency bottleneck**: Gateway model inherent. Every frame:
  remote host → guacd (VNC/RDP decode) → Guacamole protocol encode
  → WebSocket → browser → canvas ops. User reports 10× bandwidth
  vs native RDP and 3× runtime inflation on throughput-sensitive
  workloads. Lossless WebP (PR #322) helps scrolling/window-move
  specifically. Competitive for occasional admin, not sustained
  interactive.
- **Input capture**: Browser handlers serialize to Guacamole
  `mouse` + `key` instructions (X11 keysyms). IME + non-US layouts
  are known pain points (well-documented in forums).
- **Multi-streaming**: Audio (Ogg/Vorbis or raw PCM), clipboard
  (MIME-typed content), file transfer (virtual-filesystem
  abstraction) all multiplex over the same WebSocket. Lesson: one
  transport, many sub-streams with MIME typing — simple, works,
  but serial head-of-line blocking when one stream is huge.

## 4. Screen-capture libraries (2026)

### 4.1 Linux

- **Wayland sanctioned path**: XDG Desktop Portal → PipeWire.
- `wlr-screencopy-unstable-v1` works on wlroots compositors
  (Sway, Hyprland) but not GNOME/KDE.
- `ext-image-capture-source` is forward-looking Wayland-standard
  replacement; poor compositor support.
- `lamco-pipewire` + `lamco-portal` — "battle-tested in
  production, now open source" per their crates.io description;
  DMA-BUF zero-copy.
- `xcap` — X11 everywhere X11 is still installed.
- **Consent caveat**: No Wayland path gives consent-free capture.
  Portal always prompts. Deliberate, not fixable.

### 4.2 macOS

- `screencapturekit` (crate 1.5.4, actively maintained) —
  ScreenCaptureKit wrapper, macOS 12.3+, zero-copy GPU access,
  async, content picker.
- `objc2-screen-capture-kit` — lower-level objc2 binding if
  avoiding wrapper.

### 4.3 Windows

- `windows-capture` — Graphics Capture API (WGC), modern path.
- `captrs` — Desktop Duplication via DXGI, last updated 2020
  (dormant).
- WGC is Microsoft-blessed forward path, handles HDR / multi-
  monitor / DPI more cleanly than DXGI.

### 4.4 Cross-platform

- `scap` (CapSoftware) — newest credible cross-platform, author
  motivated by "non-performant, outdated, or very platform-
  specific" existing tooling.
- `captrs` — dormant.
- Pragmatic 2026: `scap` as starting ceiling OR platform-specific
  crates + own abstraction.

## 5. Hardware video encoding

### 5.1 `ffmpeg-next`

Mature. Covers everything. Heavy dependency: full libavcodec /
libavformat / libavutil / libswscale / libswresample; libclang at
build; glibc headers. Symthaea already uses it in
`symthaea-phone-embodiment`. Covers VAAPI / VideoToolbox / NVENC /
QSV / AMF / Vulkan-encode via hwaccel contexts.

### 5.2 Direct platform APIs

- VAAPI: `libva-sys` Rust bindings, no high-level wrapper.
- VideoToolbox: partial coverage in `objc2-video-toolbox`.
- Media Foundation: `windows-rs` first-party bindings.

Direct APIs win on binary size + dependency graph. Lose on
reimplementing bitstream packaging, SPS/PPS handling, rate
control.

### 5.3 Pragmatic 2026 choice

For a mid-sized project needing H.264+HEVC across three OSes with
hardware acceleration: `ffmpeg-next` is the adult choice. RustDesk's
`hwcodec` is the reference pattern (curated FFmpeg wrapper).
Binary-size cost real but survivable.

### 5.4 AV1

- `rav1e`: AV1-only Rust-native, excellent quality. **Too slow for
  real-time interactive above 720p** per xiph benchmarks.
- SVT-AV1: production real-time AV1 encoder, C.
- Browser decode: Chrome/Edge/Firefox desktop yes; Safari Apple
  Silicon only.
- 2026 verdict: AV1 not primary for remote-desktop. H.264
  universal, VP9 universally supported in WebCodecs.

## 6. Input injection

### 6.1 Linux

- `uinput` via `evdev` is baseline for X11 + "you control the box"
  scenarios.
- Wayland fundamentally restrictive by design. Sanctioned paths:
  - `libei` (Emulated Input) — new standard, compositor-
    cooperative, maturing.
  - `xdg-desktop-portal` RemoteDesktop — prompts user, issues
    libei session.
  - `virtual_keyboard` + `input_method` wlroots protocols (Sway/
    Hyprland only).
- No way to inject input on GNOME/KDE Wayland without user consent
  via portal — by design.

### 6.2 macOS

- `CGEventPost` via `core-graphics-sys` or `core-graphics` crate.
  Accessibility permission grant required (System Settings).

### 6.3 Windows

- `SendInput` via `windows-rs`. `enigo` and `winput` both wrap it.
  UAC-elevated windows require matching elevation (UIPI).

### 6.4 Cross-platform

- `enigo 0.5.x` — leader, actively maintained. Wayland support
  **explicitly experimental**; text-entry path "often simulates
  the wrong characters" (README). Alpha on Wayland. Per-platform
  backend behind own trait is safer.

## 7. Browser viewer

### 7.1 Canvas 2D at scale

`putImageData` at 1440p (2560×1440 × 4 bytes = ~14 MB/frame). At
30fps: 420 MB/s through CPU path. Canvas 2D chokes on sustained
pixel updates vs WebGL. Likely caps at ~720p@30 or 1080p@15 for
product viewer before GC pressure + main-thread contention.

### 7.2 WebCodecs

- H.264 decode: Chrome/Edge/Firefox desktop + Android (Firefox
  Android lacks WebCodecs entirely). Safari narrower.
- HEVC decode: Safari native; Chrome/Edge partial; Firefox no.
- AV1 decode: Chrome/Edge/Firefox desktop yes; Safari Apple
  Silicon only.
- Per Jan–Mar 2026 webcodecsfundamentals dataset (1.1M sessions):
  **VP9 Profile 0 ≈ H.264 universally**, slight edge. H.264
  Baseline is absolute floor.

### 7.3 WebGL / WebGPU

- WebGL ~1.66× Canvas 2D for video processing. Scales to 50k
  objects @ 58fps where Canvas 2D drops to 22fps.
- RGBA frame blit via texture upload + full-screen quad — path of
  least resistance past 720p.
- WebGPU: shipping 2026 in Chrome/Edge; Safari 17+; Firefox
  behind flag. WebGL2 still safer floor.

### 7.4 Input event fidelity

- `KeyboardEvent.code` (physical) vs `.key` (layout-mapped) — want
  `code`, reconstruct server-side, else AZERTY/Dvorak/CJK breaks.
- IME: `compositionstart` / `compositionupdate` / `compositionend`.
- Touch: use `PointerEvent` not `TouchEvent`.
- Gamepad: separate API, workable.
- Clipboard via `navigator.clipboard`: requires permission + user
  gesture each time.

## 8. Honest MVP scope assessment

Agent's synthesis: remote-desktop product is **3–4 engineer-years
of serious work before competitive**, even with good libraries.

Surface:

- **Capture**: 3 OSes × (X11/Wayland split on Linux) ≈ 4
  implementations, each with cursor/multi-monitor/DPI/HDR edge
  cases. ~3–6 months grind per platform to feel solid.
- **Encode**: Hardware codec negotiation + fallback cascade + QoS
  (bitrate adapt) + keyframe request on loss + RoI encoding for
  interactive. ~2–3 months past "works on my rig."
- **Transport**: P2P hole punching + relay fallback + reconnect +
  session resume + recording. ~2–3 months competent shipping.
- **Input**: 3 OSes × API + layout + IME. Wayland alone eats a
  month. ~2 months.
- **Viewer (WASM)**: WebCodecs + WebGL + input + audio + clipboard
  + file transfer. ~2–3 months minimum.
- **Non-code**: installer signing (Authenticode, notarization,
  Linux packaging), auto-update, TLS-PKI, account system, MDM/MSI
  deployment, audit logging, session recording storage. Easily as
  much as code.

**Minimum for "can onboard first paying MSP"**: unattended-only
(no attended/support-code), one capture per OS (Wayland deferred
or portal-only), H.264 hardware encode only (no software fallback),
browser viewer only (no native), clipboard text only, relay-only
(no P2P), rudimentary audit log. Still ~**9–12 months for two
senior Rust engineers**. Won't beat Splashtop on feel.

**Real MSP moat**: (a) admin console, (b) agent update + remote-
exec reliability, (c) PSA/RMM integrations. ScreenConnect's
"richness and complexity" is its retention.

## 9. Sources (landscape research)

Landscape research consolidated the following (raw links kept for
audit):

- RustDesk Video Capture + Encoding (DeepWiki), libs/scrap/src/
  common/codec.rs, discussions #8828 #10300 #11144, LICENCE
  (AGPL), Client-Server Communication (DeepWiki), rustdesk-server
  Performance Tuning (DeepWiki), AGPL Enterprise Compliance
  discussion #12099
- BetterDesk clean-room server
- Apache Guacamole: Implementation + Architecture, Protocol
  Reference, Guacamole Protocol, WebP PR #322, SourceForge
  throughput thread
- XCap, Lamco PipeWire, Lamco XDG portal, screencapturekit,
  windows-capture, CapSoftware scap, captrs (dormant)
- FFmpeg 6.1 Vulkan+VAAPI AV1 release notes, FFmpeg hardware
  acceleration overview, xiph/rav1e
- enigo README + CHANGES (Wayland caveats)
- WebCodecs codec analysis (1M sessions Jan-Mar 2026), caniuse
  WebCodecs, 2D vs WebGL canvas performance benchmark
- 2026 TeamViewer alternatives + ScreenConnect-vs-TeamViewer 2026
  comparisons
