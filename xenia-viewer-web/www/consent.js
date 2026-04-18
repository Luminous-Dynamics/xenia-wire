// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

import init, { WasmConsentCeremony, wireVersion } from "./pkg/xenia_viewer_web.js";

let ceremony;
let activeRequestId = null;
let frameCounter = 1;

const $ = (id) => document.getElementById(id);

function shortHex(hex, n = 8) {
  return `${hex.slice(0, n)}…${hex.slice(-n)}`;
}

function updateState() {
  const techState = ceremony.technicianConsentState();
  const userState = ceremony.endUserConsentState();
  const techEl = $("tech-state");
  const userEl = $("user-state");
  techEl.textContent = techState;
  techEl.className = `state ${techState}`;
  userEl.textContent = userState;
  userEl.className = `state ${userState}`;

  // Seal-frame button enabled iff Approved.
  $("btn-seal-frame").disabled = techState !== "Approved";
  // Revoke shown only when user is Approved.
  $("revoke-controls").style.display = userState === "Approved" ? "" : "none";
  // Request button disabled after first issue.
  $("btn-request").disabled = techState !== "AwaitingRequest";
}

function log(kind, text) {
  const logEl = $("log");
  const line = document.createElement("div");
  line.className = kind;
  const ts = new Date().toLocaleTimeString();
  line.textContent = `[${ts}] ${text}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function resetCeremony() {
  ceremony = new WasmConsentCeremony();
  activeRequestId = null;
  frameCounter = 1;
  $("tech-pubkey").textContent = shortHex(ceremony.technicianPubkeyHex(), 10);
  $("user-pubkey").textContent = shortHex(ceremony.endUserPubkeyHex(), 10);
  $("request-received").style.display = "none";
  $("no-request").style.display = "";
  $("log").innerHTML = "";
  updateState();
  log("meta", `xenia-viewer-web using xenia-wire ${wireVersion()} — ceremony initialized`);
}

async function main() {
  await init();
  resetCeremony();

  $("btn-request").addEventListener("click", () => {
    const scope = parseInt($("scope").value, 10);
    const reason = $("reason").value.trim() || "(no reason)";
    const duration = parseInt($("duration").value, 10) || 1800;
    try {
      const envelope = ceremony.technicianSignRequest(scope, reason, BigInt(duration));
      log("ok", `technician → sealed ConsentRequest (${envelope.length} bytes), state: Requested`);
      // Hand the envelope to the user side.
      const details = ceremony.endUserOpenRequest(envelope);
      activeRequestId = details.request_id;
      log("ok", `end-user ← opened, signature verified: ${details.verified}`);
      $("request-details").innerHTML = `
        <div>From <code>${shortHex(details.requester_pubkey_hex, 8)}</code></div>
        <div>Scope: <strong>${details.scope}</strong></div>
        <div>Valid until: ${new Date(details.valid_until * 1000).toLocaleString()}</div>
        <div>Reason: <em>${escapeHtml(details.reason)}</em></div>
        <div>Signature valid: ${details.verified ? "✓" : "✗"}</div>
      `;
      $("no-request").style.display = "none";
      $("request-received").style.display = "";
      updateState();
    } catch (e) {
      log("err", `request failed: ${e}`);
    }
  });

  $("btn-approve").addEventListener("click", () => handleResponse(true));
  $("btn-deny").addEventListener("click", () => handleResponse(false));

  function handleResponse(approved) {
    if (activeRequestId === null) {
      log("err", "no active request");
      return;
    }
    try {
      const envelope = ceremony.endUserSignResponse(
        BigInt(activeRequestId),
        approved,
        approved ? "" : "not right now"
      );
      log("ok", `end-user → sealed ConsentResponse{approved=${approved}} (${envelope.length} bytes)`);
      const details = ceremony.technicianOpenResponse(envelope);
      log("ok", `technician ← opened, verified: ${details.verified}, approved: ${details.approved}`);
      $("request-received").style.display = "none";
      updateState();
    } catch (e) {
      log("err", `response failed: ${e}`);
    }
  }

  $("btn-seal-frame").addEventListener("click", () => {
    try {
      const payload = new TextEncoder().encode(`frame #${frameCounter} at ${Date.now()}`);
      const envelope = ceremony.technicianSealFrame(BigInt(frameCounter), payload);
      log("ok", `FRAME sealed (${envelope.length} bytes, seq=${frameCounter})`);
      frameCounter++;
    } catch (e) {
      log("err", `FRAME seal failed: ${e}`);
    }
  });

  $("btn-revoke").addEventListener("click", () => {
    if (activeRequestId === null) return;
    try {
      const envelope = ceremony.endUserRevoke(BigInt(activeRequestId), "session complete");
      log("ok", `end-user → sealed ConsentRevocation (${envelope.length} bytes)`);
      const details = ceremony.technicianOpenRevocation(envelope);
      log("ok", `technician ← revocation verified: ${details.verified}`);
      updateState();
      // After revocation, further FRAME seals should fail.
      try {
        ceremony.technicianSealFrame(BigInt(frameCounter), new TextEncoder().encode("after-revoke"));
        log("err", "unexpected: FRAME sealed after revoke");
      } catch (e) {
        log("ok", `post-revoke FRAME correctly rejected: ${e}`);
      }
    } catch (e) {
      log("err", `revoke failed: ${e}`);
    }
  });

  $("btn-reset").addEventListener("click", resetCeremony);
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

main().catch((e) => {
  const err = document.createElement("div");
  err.style.color = "red";
  err.textContent = `init failed: ${e}`;
  document.body.prepend(err);
});
