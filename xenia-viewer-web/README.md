# xenia-viewer-web

Frontend surface for the Xenia wire protocol. Four pages, all
running entirely in WebAssembly — no server, no network, no real
session. Intended as the public-facing introduction to what Xenia
*is* for visitors who aren't going to read SPEC.md first.

## Pages

| Path | Purpose |
|------|---------|
| `www/index.html` | Landing page — overview, links to crate/spec/paper, cards pointing to the three interactive demos. Static, no WASM. |
| `www/demo.html` | Minimal 30-line seal/open roundtrip. Confirms the wire works on wasm32. |
| `www/consent.html` | Interactive walk-through of the consent ceremony. Two-sided UI (technician + end-user), real Ed25519 signing, state machine visible, revocation flow. **This is the distinctive-feature demo.** |
| `www/viewer.html` | Viewer MVP — canvas renders synthetic 160×120 RGBA frames at ~15 fps sealed as `Frame` envelopes; mouse/keyboard captured as `Input` envelopes on the reverse path. Loopback; no real server. |

## Build

Requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```console
$ cargo install wasm-pack
```

Build the WASM glue into `www/pkg/`:

```console
$ cd xenia-viewer-web
$ wasm-pack build --target web --out-dir www/pkg
```

This produces `www/pkg/xenia_viewer_web.js` (JS shim) +
`www/pkg/xenia_viewer_web_bg.wasm` (~200 KB).

## Serve locally

Any static file server works. Simplest:

```console
$ cd xenia-viewer-web/www
$ python3 -m http.server 8080
```

Open <http://localhost:8080> and click through the cards.

## Deploy

The entire `www/` directory (including `pkg/` after `wasm-pack build`)
is a static site. Deploy to any static host:

- **Cloudflare Pages** — connect the repo, set build command
  `cargo install wasm-pack && wasm-pack build --target web --out-dir www/pkg`
  in `xenia-viewer-web/`, output dir `xenia-viewer-web/www`.
- **GitHub Pages** — build locally, push `www/` to a `gh-pages`
  branch.
- **S3 / R2 / Backblaze B2** — any object store with static-site
  hosting.

The Luminous Dynamics infrastructure would host at
`xenia.luminousdynamics.io` or similar; deployment is pending the
launch-signal decision (see `FOLLOW_UPS.md`).

## What these demos are NOT

- **Not** a real remote-desktop viewer. That's Track-B engineering —
  a real server-side screen capture, a real transport
  (WebSocket/WebTransport), real input injection, session lifecycle.
- **Not** a production consent UX. The walk-through shows the
  protocol flow; a real end-user consent dialog in a deployed MSP
  tool would want accessibility review, cancel-by-default design,
  device-key storage via WebAuthn or similar.
- **Not** a secure demo of key management. The pages use random
  AEAD keys generated in-browser — in a real deployment, keys come
  from the handshake layer (ML-KEM-768 + Ed25519, Track 2.5).

## WASM API surface

`src/lib.rs` exposes three JS-facing types:

- `WasmSession` — thin wrapper around `xenia_wire::Session` for the
  minimal demo.
- `WasmConsentCeremony` — two-sided fixture that owns both
  technician and end-user Sessions + Ed25519 keypairs. Exposes every
  step of the ceremony (sign request, open request, sign response,
  open response, seal frame, revoke, open revocation) so `consent.js`
  can drive the walk-through without re-implementing signing logic
  in JavaScript.
- `WasmViewer` — paired sender+receiver with consent pre-approved,
  plus `roundTripFrame` / `roundTripInput` loopback helpers so
  `viewer.js` can render realistic-shaped traffic.

## Why a separate crate?

`xenia-wire` is a pure-Rust library with no wasm-bindgen dependency.
Keeping the WASM bindings in a separate crate preserves the core
crate's dependency hygiene — a server-side adopter never pulls
wasm-bindgen, js-sys, web-sys, or console_error_panic_hook.

## License

Dual-licensed under Apache-2.0 OR MIT, matching `xenia-wire`.
Not published to crates.io (`publish = false` in `Cargo.toml`);
this crate is infrastructure for the frontend, not a library.
