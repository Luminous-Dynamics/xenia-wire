#!/usr/bin/env node
// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Independent (non-Rust) runner for the consent event-sequence vectors
// (10-12), the companion to verify.mjs's envelope checks. It reimplements the
// `observe_consent` state machine from SPEC.md section 12.6.1 (normative
// transition table) and replays each vector's line-oriented DSL, asserting
// EXPECT_STATE / EXPECT_VIOLATION exactly as the Rust reference runner
// (tests/violation_vectors.rs) does. No xenia-wire code, no dependencies.
//
// Run:  node test-vectors/conformance/verify-consent.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

// ── observe_consent: SPEC section 12.6.1 transition table (normative) ──────
//
// `session` = { state, active, lastResponse }. Returns { session, violation }
// where `violation` is null on a clean transition, or
// { variant, requestId, prior?, new? } on a violation (state unchanged).
function observeConsent(session, event) {
  const { kind, id } = event;
  const s = session.state;
  const active = session.active;

  const unchanged = (violation) => ({ session, violation });
  const to = (state, patch = {}) => ({
    session: { state, active: session.active, lastResponse: session.lastResponse, ...patch },
    violation: null,
  });
  const stale = () =>
    unchanged({ variant: "StaleResponseForUnknownRequest", requestId: id });

  if (s === "LegacyBypass") return to("LegacyBypass"); // sticky, all no-ops

  if (s === "AwaitingRequest") {
    if (kind === "Request") return to("Requested", { active: id, lastResponse: null });
    if (kind === "Revocation")
      return unchanged({ variant: "RevocationBeforeApproval", requestId: id });
    return stale(); // any Response* with no prior request
  }

  if (s === "Requested") {
    if (kind === "Request") {
      return id > active
        ? to("Requested", { active: id, lastResponse: null }) // replacement
        : to("Requested"); // stale drop, no-op
    }
    if (kind === "Revocation")
      return unchanged({ variant: "RevocationBeforeApproval", requestId: id });
    // Response*
    if (id !== active) return stale();
    if (kind === "ResponseApproved") return to("Approved", { lastResponse: true });
    if (kind === "ResponseDenied") return to("Denied", { lastResponse: false });
  }

  if (s === "Approved") {
    if (kind === "Request") {
      return id > active
        ? to("Requested", { active: id, lastResponse: null }) // fresh ceremony
        : to("Approved"); // stale, no-op
    }
    if (kind === "Revocation") {
      return id === active ? to("Revoked") : to("Approved"); // stale revocation no-op
    }
    if (id !== active) return stale();
    if (kind === "ResponseApproved") return to("Approved"); // idempotent
    if (kind === "ResponseDenied")
      return unchanged({ variant: "ContradictoryResponse", requestId: id, prior: true, new: false });
  }

  if (s === "Denied") {
    if (kind === "Request") {
      return id > active
        ? to("Requested", { active: id, lastResponse: null }) // fresh ceremony
        : to("Denied"); // stale, no-op
    }
    if (kind === "Revocation") return to("Denied"); // nothing to revoke
    if (id !== active) return stale();
    if (kind === "ResponseDenied") return to("Denied"); // idempotent
    if (kind === "ResponseApproved")
      return unchanged({ variant: "ContradictoryResponse", requestId: id, prior: false, new: true });
  }

  if (s === "Revoked") {
    if (kind === "Request" && id > active)
      return to("Requested", { active: id, lastResponse: null }); // fresh ceremony
    return to("Revoked"); // any other, no-op
  }

  throw new Error(`unhandled (${s}, ${kind})`);
}

// ── Vector DSL parser + driver ─────────────────────────────────────────────
function runVector(relPath) {
  const text = readFileSync(join(VECTORS_DIR, relPath), "utf8");
  const allLines = text.split("\n");
  // The marker is a line that is *exactly* `---BEGIN---`. Match on the whole
  // line, not a substring -- the prose above it quotes "---BEGIN---" when
  // documenting the format, and indexOf would match that first.
  const markerIdx = allLines.findIndex((l) => l.trim() === "---BEGIN---");
  if (markerIdx === -1) throw new Error("missing ---BEGIN--- marker line");
  const lines = allLines
    .slice(markerIdx + 1)
    .map((l) => l.trim())
    .filter((l) => l !== "" && !l.startsWith("#") && !l.startsWith("-"));

  let session = null;
  let last = null; // { session, violation } from the most recent EVENT

  for (const line of lines) {
    const [directive, ...rest] = line.split(/\s+/);
    switch (directive) {
      case "INITIAL":
        session = { state: rest[0], active: undefined, lastResponse: null };
        break;
      case "EVENT": {
        const [kind, idStr] = rest;
        last = observeConsent(session, { kind, id: Number(idStr) });
        session = last.session; // state unchanged on violation (session is the same object)
        break;
      }
      case "EXPECT_STATE":
        if (session.state !== rest[0]) {
          throw new Error(`expected state ${rest[0]}, got ${session.state}`);
        }
        break;
      case "EXPECT_VIOLATION": {
        const [variant, idStr, prior, nw] = rest;
        const v = last && last.violation;
        if (!v) throw new Error(`expected violation ${variant} ${idStr}, got none`);
        if (v.variant !== variant || v.requestId !== Number(idStr)) {
          throw new Error(
            `expected violation ${variant} ${idStr}, got ${v.variant} ${v.requestId}`,
          );
        }
        if (variant === "ContradictoryResponse") {
          if (String(v.prior) !== prior || String(v.new) !== nw) {
            throw new Error(
              `contradictory prior/new: expected ${prior}/${nw}, got ${v.prior}/${v.new}`,
            );
          }
        }
        break;
      }
      default:
        throw new Error(`unknown directive: ${directive}`);
    }
  }
}

// ── Harness ────────────────────────────────────────────────────────────────
const vectors = [
  ["10 revocation_before_approval", "10_revocation_before_approval.txt"],
  ["11 contradictory_response", "11_contradictory_response.txt"],
  ["12 stale_response", "12_stale_response.txt"],
];

console.log("xenia-wire consent state-machine conformance (Node.js)\n");
let passed = 0;
let failed = 0;
for (const [name, file] of vectors) {
  try {
    runVector(file);
    console.log(`  ✓ ${name}`);
    passed += 1;
  } catch (e) {
    console.log(`  ✗ ${name}\n      ${e.message}`);
    failed += 1;
  }
}
console.log(
  `\n${failed === 0 ? "✓ PASS" : "✗ FAIL"} — ${passed} passed, ${failed} failed`,
);
process.exit(failed === 0 ? 0 : 1);
