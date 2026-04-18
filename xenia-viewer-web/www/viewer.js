// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

import init, { WasmViewer, wireVersion } from "./pkg/xenia_viewer_web.js";

const CANVAS_W = 160;
const CANVAS_H = 120;
const FRAME_INTERVAL_MS = 66; // ~15 fps

let viewer;
let running = false;
let frameCount = 0;
let inputCount = 0;
let totalBytes = 0;
let lastFpsCheck = performance.now();
let framesSinceFpsCheck = 0;
let streamHandle = null;

const $ = (id) => document.getElementById(id);

function log(kind, text) {
  const logEl = $("log");
  const line = document.createElement("div");
  line.className = kind;
  const ts = new Date().toLocaleTimeString();
  line.textContent = `[${ts}] ${text}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

// Generate a synthetic frame. Each frame is a 160×120 RGBA buffer with
// a time-varying pattern (rolling sine wave + gradient) so the
// roundtrip is visible.
function synthFrame(t) {
  const buf = new Uint8ClampedArray(CANVAS_W * CANVAS_H * 4);
  for (let y = 0; y < CANVAS_H; y++) {
    for (let x = 0; x < CANVAS_W; x++) {
      const i = (y * CANVAS_W + x) * 4;
      const r = 128 + 127 * Math.sin((x + t) * 0.08);
      const g = 128 + 127 * Math.sin((y + t * 0.7) * 0.09 + 2);
      const b = 128 + 127 * Math.sin((x + y + t * 1.3) * 0.07 + 4);
      buf[i] = r | 0;
      buf[i + 1] = g | 0;
      buf[i + 2] = b | 0;
      buf[i + 3] = 255;
    }
  }
  return new Uint8Array(buf.buffer);
}

function renderFrame(ctx, rgbaBytes) {
  const imgData = new ImageData(
    new Uint8ClampedArray(rgbaBytes),
    CANVAS_W,
    CANVAS_H
  );
  // Render into a tiny off-screen canvas then scale up pixelated.
  const off = document.createElement("canvas");
  off.width = CANVAS_W;
  off.height = CANVAS_H;
  off.getContext("2d").putImageData(imgData, 0, 0);
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(off, 0, 0, CANVAS_W, CANVAS_H, 0, 0, ctx.canvas.width, ctx.canvas.height);
}

function updateStats() {
  $("stat-frames").textContent = frameCount.toLocaleString();
  $("stat-inputs").textContent = inputCount.toLocaleString();
  $("stat-bytes").textContent = totalBytes.toLocaleString();
  const now = performance.now();
  const elapsed = now - lastFpsCheck;
  if (elapsed > 500) {
    const fps = (framesSinceFpsCheck * 1000) / elapsed;
    $("stat-fps").textContent = fps.toFixed(1);
    framesSinceFpsCheck = 0;
    lastFpsCheck = now;
  }
}

function startStream(ctx) {
  if (running) return;
  running = true;
  $("btn-start").disabled = true;
  $("btn-stop").disabled = false;

  let t = 0;
  const tick = () => {
    if (!running) return;
    const rgba = synthFrame(t);
    try {
      const opened = viewer.roundTripFrame(BigInt(frameCount), rgba);
      renderFrame(ctx, opened);
      frameCount++;
      framesSinceFpsCheck++;
      totalBytes += opened.length;
      updateStats();
    } catch (e) {
      log("meta", `frame seal/open failed: ${e}`);
    }
    t += 3;
    streamHandle = setTimeout(tick, FRAME_INTERVAL_MS);
  };
  tick();
  log("ok", `stream started — ${CANVAS_W}×${CANVAS_H} @ ~${Math.round(1000 / FRAME_INTERVAL_MS)} fps, loopback`);
}

function stopStream() {
  running = false;
  if (streamHandle !== null) {
    clearTimeout(streamHandle);
    streamHandle = null;
  }
  $("btn-start").disabled = false;
  $("btn-stop").disabled = true;
  log("meta", "stream stopped");
}

async function main() {
  await init();
  viewer = new WasmViewer();
  log("meta", `xenia-viewer-web using xenia-wire ${wireVersion()} — viewer ready`);

  const canvas = $("screen");
  const ctx = canvas.getContext("2d");
  // Upscale the 160×120 to 320×240 for on-page visibility.
  canvas.width = CANVAS_W * 2;
  canvas.height = CANVAS_H * 2;

  $("btn-start").addEventListener("click", () => startStream(ctx));
  $("btn-stop").addEventListener("click", stopStream);
  $("btn-clear").addEventListener("click", () => ($("log").innerHTML = ""));

  // Input capture. All events are sealed as Input envelopes on the
  // reverse path; we just print the loopback-decoded JSON.
  function sealEvent(type, detail) {
    const json = JSON.stringify({ type, ...detail, t: Date.now() });
    try {
      const decoded = viewer.roundTripInput(json);
      inputCount++;
      // Estimate bytes — rough approximation of envelope overhead.
      totalBytes += decoded.length + 12 + 16 + 20;
      log("input", `${type}: ${decoded.slice(0, 80)}${decoded.length > 80 ? "…" : ""}`);
      updateStats();
    } catch (e) {
      log("meta", `input seal failed: ${e}`);
    }
  }

  canvas.addEventListener("mousemove", (e) => {
    const r = canvas.getBoundingClientRect();
    // Normalize to 0..1 so the payload is transport-stable.
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    sealEvent("mousemove", { x: +x.toFixed(3), y: +y.toFixed(3) });
  });

  canvas.addEventListener("mousedown", (e) => {
    const r = canvas.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    sealEvent("mousedown", { x: +x.toFixed(3), y: +y.toFixed(3), button: e.button });
  });

  canvas.addEventListener("keydown", (e) => {
    sealEvent("keydown", { key: e.key, code: e.code });
    e.preventDefault();
  });
}

main().catch((e) => {
  const err = document.createElement("div");
  err.style.color = "red";
  err.textContent = `init failed: ${e}`;
  document.body.prepend(err);
});
