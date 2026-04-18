#!/usr/bin/env python3
# Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
Dev-only static file server for the xenia-viewer-web browser pages.

Two-terminal flow on a VM:

    # terminal 1 — xenia-peer daemon (in the xenia-peer repo)
    cargo run --release -p xenia-peer -- \\
        --listen 0.0.0.0:4747 --transport ws --codec passthrough \\
        --width 320 --height 200 --fps 30 --frames 0

    # terminal 2 — serve the WASM viewer pages (in this repo)
    python3 xenia-viewer-web/serve-www.py --host 0.0.0.0 --port 8080

Then on a phone browser:

    http://<vm-ip>:8080/daemon.html?peer=ws://<vm-ip>:4747&autoconnect=1

The page connects over WebSocket, opens sealed envelopes via the
xenia-wire WASM bindings, and renders each frame to a canvas.

NOT for production. This is an http.server subclass with MIME
types for .wasm and long-lived connections — no TLS, no auth, no
CSP. Run inside Tailscale / LAN / a trusted dev VM.
"""
import argparse
import http.server
import mimetypes
import os
import socketserver
import sys


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with .wasm MIME + no-cache headers."""

    # Force the right type so browsers don't refuse to instantiate
    # the .wasm as a module.
    extensions_map = dict(mimetypes.types_map, **{
        ".wasm": "application/wasm",
        ".js": "application/javascript",
        ".mjs": "application/javascript",
    })

    def end_headers(self):
        # Dev-only: disable caching so wasm-pack rebuilds are picked
        # up without a hard-refresh.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Quieter than the default — we don't need a line per favicon.ico 404.
        line = fmt % args
        if " 200 " in line or " 101 " in line or " 304 " in line:
            return
        sys.stderr.write("[serve-www] " + line + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Dev static-file server for xenia-viewer-web/www/",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (0.0.0.0 for LAN / Tailscale access)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--root", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "www"))
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        sys.exit(f"serve-www: no such dir: {args.root}")

    os.chdir(args.root)
    with socketserver.ThreadingTCPServer((args.host, args.port), QuietHandler) as httpd:
        actual_host, actual_port = httpd.server_address[:2]
        print(f"serve-www: http://{actual_host}:{actual_port}/")
        print(f"serve-www: daemon viewer → http://{actual_host}:{actual_port}/daemon.html")
        print("serve-www: Ctrl-C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nserve-www: shutting down.")


if __name__ == "__main__":
    main()
