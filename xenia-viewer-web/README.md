# xenia-viewer-web

A WebAssembly demo of the Xenia wire protocol. Seals and opens a frame
in the browser; demonstrates that `xenia-wire` works on the web platform.

**This is not a full MSP-style remote-desktop viewer.** It is a
reference demo. No WebSocket, no live server, no real session — just
the sealed-envelope roundtrip rendered as text.

## Build

Requires `wasm-pack`:

```console
$ cargo install wasm-pack
```

Then build the wasm-bindgen glue into `www/pkg/`:

```console
$ cd xenia-viewer-web
$ wasm-pack build --target web --out-dir www/pkg
```

## Serve

Any static file server works. Simplest:

```console
$ cd xenia-viewer-web/www
$ python3 -m http.server 8080
```

Open <http://localhost:8080> and click the "Seal + open" button.

## What the demo shows

1. Two `WasmSession` instances (sender + receiver) are constructed
   with random `source_id` + `epoch` sourced from `crypto.getRandomValues`.
2. Both sides install the same 32-byte fixture key.
3. The sender seals a user-provided payload as a `Frame`; the envelope
   bytes are rendered as hex.
4. The receiver opens the envelope; the plaintext is shown.
5. A second open attempt on the same bytes is rejected by the
   sliding replay window.

## Deployment

The demo is a static site (HTML + WASM glue + JS). It deploys to
any static-site host — GitHub Pages, Cloudflare Pages, S3/R2/B2 —
by serving `www/` contents after running `wasm-pack build`.

The authors do not currently host the demo. Integrators are welcome
to fork and host; please do not use the Luminous Dynamics name
without separate permission.

## Why a separate crate?

`xenia-wire` is a pure-Rust library with no wasm-bindgen dependency.
Keeping the WASM bindings in a separate crate preserves the core
crate's dependency hygiene — a server-side Rust application adopting
`xenia-wire` never pulls in `wasm-bindgen`, `js-sys`, or `web-sys`.
