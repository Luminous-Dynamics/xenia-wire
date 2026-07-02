// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Browser viewer for the xenia-peer daemon.
// Connects over WebSocket, decrypts sealed envelopes via the
// xenia-wire WASM bindings, parses the passthrough payload, and
// renders each frame to a canvas.

import init, { WasmSession, WasmHandshake, openDaemonFrame, wireVersion } from "./pkg/xenia_viewer_web.js";

// MUST match the daemon's --source-id-hex default.
const DEFAULT_SOURCE_ID_HEX = "7878656e69617068";
const DEFAULT_EPOCH = 0x01;

// UI handles
const $ = (id) => document.getElementById(id);
const elUrl = $("url");
const btnConnect = $("btn-connect");
const btnDisconnect = $("btn-disconnect");
const canvas = $("canvas");
const ctx = canvas.getContext("2d", { alpha: false, desynchronized: true });
const sState = $("s-state");
const sFrames = $("s-frames");
const sLast = $("s-last");
const sFps = $("s-fps");
const sErr = $("s-err");
const sWire = $("s-wire");

// App state (one active session at a time)
let session = null;
let socket = null;
let frameCount = 0;
let recentFrameTimes = [];
// Real PQC handshake state machine (ML-KEM-768 + Ed25519 + HKDF-SHA-256,
// see src/handshake.rs). The daemon always speaks this handshake first —
// "awaiting-hello": expecting the daemon's HostHello as the first binary
// message; "awaiting-finalize": ViewerResponse sent, expecting HostFinalize;
// "done": session key installed, subsequent messages are sealed frames.
let handshake = null;
let handshakeStage = "idle";

function setState(s, color) {
  sState.textContent = s;
  sState.style.color = color || "";
}
function setError(msg) {
  sErr.textContent = msg || "–";
}
function updateFps() {
  const n = recentFrameTimes.length;
  if (n < 2) { sFps.textContent = "–"; return; }
  const span = (recentFrameTimes[n - 1] - recentFrameTimes[0]) / 1000;
  if (span <= 0) { sFps.textContent = "–"; return; }
  sFps.textContent = ((n - 1) / span).toFixed(1);
}

function resizeCanvas(w, h) {
  if (canvas.width !== w) canvas.width = w;
  if (canvas.height !== h) canvas.height = h;
}

function drawFrame(frame) {
  resizeCanvas(frame.width, frame.height);
  // frame.rgba is a Uint8Array of length width*height*4. We need a
  // Uint8ClampedArray for ImageData — wrap the underlying buffer
  // directly to avoid a copy.
  const clamped = new Uint8ClampedArray(frame.rgba.buffer, frame.rgba.byteOffset, frame.rgba.byteLength);
  const imageData = new ImageData(clamped, frame.width, frame.height);
  ctx.putImageData(imageData, 0, 0);

  frameCount += 1;
  sFrames.textContent = String(frameCount);
  sLast.textContent = `${frame.width}×${frame.height} (id ${frame.frame_id})`;

  const now = performance.now();
  recentFrameTimes.push(now);
  while (recentFrameTimes.length > 32) recentFrameTimes.shift();
  updateFps();
}

function handleMessage(event) {
  if (typeof event.data === "string") {
    setError("daemon sent a text frame; expected binary");
    return;
  }
  // event.data is ArrayBuffer or Blob depending on binaryType
  const bytes = event.data instanceof ArrayBuffer
    ? new Uint8Array(event.data)
    : null;
  if (!bytes) {
    setError("message data is not an ArrayBuffer; set socket.binaryType = 'arraybuffer'");
    return;
  }

  if (handshakeStage === "awaiting-hello") {
    try {
      const viewerResponse = handshake.begin(bytes);
      socket.send(viewerResponse);
      handshakeStage = "awaiting-finalize";
      setState("handshaking (2/2)…", "var(--accent)");
      setError(null);
    } catch (e) {
      setError(`handshake (HostHello): ${e.message || e}`);
      disconnect();
    }
    return;
  }

  if (handshakeStage === "awaiting-finalize") {
    try {
      const sessionKey = handshake.finish(bytes);
      session = new WasmSession();
      session.installKey(sessionKey);
      handshakeStage = "done";
      setState("connected", "var(--ok)");
      setError(null);
    } catch (e) {
      setError(`handshake (HostFinalize): ${e.message || e}`);
      disconnect();
    }
    return;
  }

  if (!session) {
    setError("message received but session not ready");
    return;
  }
  try {
    const frame = openDaemonFrame(session, bytes);
    drawFrame(frame);
    setError(null);
  } catch (e) {
    setError(String(e.message || e));
  }
}

function parseSourceId(hex) {
  if (hex.length !== 16) throw new Error("source_id must be 16 hex chars");
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function disconnect() {
  if (socket) {
    try { socket.close(); } catch {}
    socket = null;
  }
  session = null;
  handshake = null;
  handshakeStage = "idle";
  frameCount = 0;
  recentFrameTimes = [];
  sFrames.textContent = "0";
  sLast.textContent = "–";
  sFps.textContent = "–";
  setState("idle", "var(--muted)");
  btnConnect.disabled = false;
  btnDisconnect.disabled = true;
}

function connect() {
  const url = elUrl.value.trim();
  if (!url.startsWith("ws://") && !url.startsWith("wss://")) {
    setError("URL must start with ws:// or wss://");
    return;
  }

  setError(null);
  setState("connecting…", "var(--accent)");

  // The daemon always speaks a real ML-KEM-768 + Ed25519 + HKDF-SHA-256
  // handshake first (xenia-peer-core::handshake, mirrored byte-for-byte
  // by WasmHandshake — see src/handshake.rs and its cross-implementation
  // test). No fixture key: the session key is derived fresh each
  // connection from the exchange below, handled in handleMessage's
  // "awaiting-hello" / "awaiting-finalize" stages.
  //
  // The `source_id` field on the receiver's Session only matters when
  // the receiver is also a SENDER — which the viewer is not yet (input
  // path is M2) — so a fresh WasmSession installed with the derived key
  // after the handshake completes is sufficient to open the daemon's
  // frames; see the AEAD/replay-window note this comment used to carry.
  try {
    handshake = new WasmHandshake();
    handshakeStage = "awaiting-hello";
  } catch (e) {
    setError(`WASM init: ${e.message || e}`);
    disconnect();
    return;
  }

  try {
    socket = new WebSocket(url);
  } catch (e) {
    setError(`WebSocket: ${e.message || e}`);
    disconnect();
    return;
  }
  socket.binaryType = "arraybuffer";

  socket.addEventListener("open", () => {
    setState("handshaking (1/2)…", "var(--accent)");
    btnConnect.disabled = true;
    btnDisconnect.disabled = false;
  });
  socket.addEventListener("message", handleMessage);
  socket.addEventListener("close", (ev) => {
    setState(`closed (${ev.code})`, "var(--err)");
    btnConnect.disabled = false;
    btnDisconnect.disabled = true;
    socket = null;
  });
  socket.addEventListener("error", () => {
    setError("WebSocket error (see browser console)");
  });
}

async function main() {
  await init();
  sWire.textContent = wireVersion();

  btnConnect.addEventListener("click", connect);
  btnDisconnect.addEventListener("click", disconnect);

  // Pre-fill URL from query string for easy phone testing:
  //   daemon.html?peer=ws://192.168.1.10:4747
  const params = new URLSearchParams(window.location.search);
  if (params.has("peer")) {
    elUrl.value = params.get("peer");
  }
  // Auto-connect if ?autoconnect=1 is in the URL — handy for
  // phones where typing the URL is annoying.
  if (params.get("autoconnect") === "1") {
    connect();
  }
}

main().catch((e) => {
  setError(`startup: ${e.message || e}`);
});
