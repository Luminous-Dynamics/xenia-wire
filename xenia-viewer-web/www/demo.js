// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Browser-side glue for the xenia-wire WASM demo. Expects
// `./pkg/xenia_viewer_web.js` to be next to this file (produced by
// `wasm-pack build --target web`).

import init, {
  WasmSession,
  sealFrame,
  openFrame,
  wireVersion,
} from "./pkg/xenia_viewer_web.js";

const FIXTURE_KEY = new Uint8Array([
  0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
  0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
  0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
  0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
]);

function hex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
}

function render(el, lines) {
  el.innerHTML = lines.map(l => {
    if (l.kind === "ok") return `<p class="ok">${l.text}</p>`;
    if (l.kind === "err") return `<p class="err">${l.text}</p>`;
    if (l.kind === "meta") return `<p class="meta">${l.text}</p>`;
    if (l.kind === "pre") return `<pre>${l.text}</pre>`;
    return `<p>${l.text}</p>`;
  }).join("");
}

async function main() {
  await init();
  console.log(`xenia-viewer-web using xenia-wire ${wireVersion()}`);

  const run = document.getElementById("run");
  const output = document.getElementById("output");

  run.addEventListener("click", () => {
    const payloadStr = document.getElementById("payload").value;
    const payload = new TextEncoder().encode(payloadStr);

    const sender = new WasmSession();
    const receiver = new WasmSession();
    sender.installKey(FIXTURE_KEY);
    receiver.installKey(FIXTURE_KEY);

    const timestampMs = BigInt(Date.now());
    const envelope = sealFrame(sender, 1n, timestampMs, payload);

    let openResult, replayResult;
    try {
      openResult = openFrame(receiver, envelope);
    } catch (e) {
      render(output, [{ kind: "err", text: `open failed: ${e}` }]);
      return;
    }

    try {
      openFrame(receiver, envelope);
      // Should have thrown — if we reach here, replay wasn't caught.
      replayResult = "UNEXPECTED: replay was accepted";
    } catch (e) {
      replayResult = String(e);
    }

    const decoded = new TextDecoder().decode(openResult.payload);

    render(output, [
      { kind: "meta", text: `xenia-wire version: ${wireVersion()}` },
      { kind: "meta", text: `sender source_id: ${sender.sourceIdHex()}` },
      { kind: "ok", text: `sealed ${payload.length}-byte plaintext → ${envelope.length}-byte envelope` },
      { kind: "pre", text: `envelope (hex):\n${hex(envelope).match(/.{1,32}/g).join("\n")}` },
      { kind: "ok", text: `opened → frame_id=${openResult.frame_id}, payload="${decoded}"` },
      { kind: "ok", text: `replay correctly rejected: ${replayResult}` },
    ]);
  });
}

main().catch(e => {
  document.getElementById("output").innerHTML =
    `<p class="err">init failed: ${e}</p>`;
});
