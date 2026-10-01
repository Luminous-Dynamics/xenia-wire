#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  fs.readFileSync(path.join(here, "..", "13_causal_authority_v1.json"), "utf8"),
);

const PROFILE = Buffer.from("xenia.external-action-authority.v1", "utf8");
const MAGIC = Buffer.concat([PROFILE, Buffer.from([0])]);
const REQUEST_DIGEST_DOMAIN = Buffer.from(
  "xenia.causal-authority.request-digest.v1\0",
  "utf8",
);
const INSTANCE_ID_DOMAIN = Buffer.from(
  "xenia.causal-authority.instance-id.v1\0",
  "utf8",
);

function fromHex(value) {
  return Buffer.from(value, "hex");
}

function hex(value) {
  return Buffer.from(value).toString("hex");
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
}

function bytes(value) {
  const body = Buffer.from(value);
  return Buffer.concat([u64(body.length), body]);
}

function string(value) {
  return bytes(Buffer.from(value, "utf8"));
}

function optionSome(value) {
  // bincode v1 Option discriminant is one byte: 0=None, 1=Some.
  return Buffer.concat([Buffer.from([1]), value]);
}

function bool(value) {
  return Buffer.from([value ? 1 : 0]);
}

function ed25519PrivateKey(seed) {
  // RFC 8410 PKCS#8 prefix for an Ed25519 32-byte private seed.
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({
    key: Buffer.concat([prefix, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32);
}

function publicKeyFromRaw(raw) {
  // RFC 8410 SPKI prefix for an Ed25519 32-byte public key.
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: "der",
    type: "spki",
  });
}

function serializeAuthority(authority) {
  return Buffer.concat([
    fromHex(authority.subject_id_hex),
    bytes(fromHex(authority.target_hex)),
    bytes(fromHex(authority.capability_hex)),
    fromHex(authority.action_digest_hex),
    fromHex(authority.parameters_digest_hex),
    bytes(fromHex(authority.max_scope_hex)),
    u64(authority.expires_at_ms),
    u32(authority.use_policy_variant),
  ]);
}

function sha256(...parts) {
  const hash = crypto.createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function expectHex(actual, expected, label) {
  assert.equal(hex(actual), expected, `${label} mismatch`);
}

assert.equal(fixture.profile, PROFILE.toString("utf8"));

const requesterSeed = fromHex(fixture.requester_seed_hex);
const responderSeed = fromHex(fixture.responder_seed_hex);
const requesterPrivate = ed25519PrivateKey(requesterSeed);
const responderPrivate = ed25519PrivateKey(responderSeed);
const requesterPublic = rawPublicKey(requesterPrivate);
const responderPublic = rawPublicKey(responderPrivate);
const fingerprint = fromHex(fixture.session_fingerprint_hex);

expectHex(requesterPublic, fixture.requester_public_key_hex, "requester public key");
expectHex(responderPublic, fixture.responder_public_key_hex, "responder public key");

const authorityPayload = serializeAuthority(fixture.authority);
expectHex(authorityPayload, fixture.expected.authority_payload_hex, "authority payload");

const causalOpaque = Buffer.concat([MAGIC, authorityPayload]);
expectHex(causalOpaque, fixture.expected.causal_opaque_hex, "causal opaque");

const causalPredicate = Buffer.concat([
  string(fixture.profile),
  bytes(causalOpaque),
]);

const requestCore = Buffer.concat([
  u64(fixture.request_id),
  requesterPublic,
  fingerprint,
  u64(fixture.valid_until),
  u32(fixture.consent_scope_variant),
  string(fixture.request_reason),
  optionSome(causalPredicate),
]);
expectHex(requestCore, fixture.expected.consent_request_core_hex, "consent request core");

const requestSignature = crypto.sign(null, requestCore, requesterPrivate);
expectHex(
  requestSignature,
  fixture.expected.consent_request_signature_hex,
  "consent request signature",
);
assert.ok(
  crypto.verify(null, requestCore, publicKeyFromRaw(requesterPublic), requestSignature),
  "request signature must verify",
);

const signedRequest = Buffer.concat([requestCore, requestSignature]);
expectHex(signedRequest, fixture.expected.consent_request_hex, "signed consent request");

const requestDigest = sha256(REQUEST_DIGEST_DOMAIN, signedRequest);
expectHex(requestDigest, fixture.expected.request_digest_hex, "request digest");

const responseCore = Buffer.concat([
  u64(fixture.request_id),
  requestDigest,
  responderPublic,
  fingerprint,
  bool(fixture.response.approved),
  u64(fixture.response.issued_at_ms),
  string(fixture.response.reason),
]);
expectHex(responseCore, fixture.expected.causal_response_core_hex, "causal response core");

const responseSignature = crypto.sign(null, responseCore, responderPrivate);
expectHex(
  responseSignature,
  fixture.expected.causal_response_signature_hex,
  "causal response signature",
);
assert.ok(
  crypto.verify(null, responseCore, publicKeyFromRaw(responderPublic), responseSignature),
  "response signature must verify",
);

const signedResponse = Buffer.concat([responseCore, responseSignature]);
expectHex(signedResponse, fixture.expected.causal_response_hex, "signed causal response");

const authorityId = sha256(
  INSTANCE_ID_DOMAIN,
  requestDigest,
  responderPublic,
  responseSignature,
);
expectHex(authorityId, fixture.expected.authority_id_hex, "authority instance id");

// Regression: changing the exact action creates a different request digest even
// when request_id and session_fingerprint remain unchanged.
const substitutedAuthority = {
  ...fixture.authority,
  action_digest_hex: "99".repeat(32),
};
const substitutedOpaque = Buffer.concat([MAGIC, serializeAuthority(substitutedAuthority)]);
const substitutedPredicate = Buffer.concat([
  string(fixture.profile),
  bytes(substitutedOpaque),
]);
const substitutedCore = Buffer.concat([
  u64(fixture.request_id),
  requesterPublic,
  fingerprint,
  u64(fixture.valid_until),
  u32(fixture.consent_scope_variant),
  string(fixture.request_reason),
  optionSome(substitutedPredicate),
]);
const substitutedSignature = crypto.sign(null, substitutedCore, requesterPrivate);
const substitutedRequest = Buffer.concat([substitutedCore, substitutedSignature]);
const substitutedDigest = sha256(REQUEST_DIGEST_DOMAIN, substitutedRequest);
assert.notDeepEqual(
  substitutedDigest,
  requestDigest,
  "same-id request substitution must change the responder-bound digest",
);

console.log("PASS: causal authority v1 cross-implementation vector");
console.log(`request_digest=${hex(requestDigest)}`);
console.log(`authority_id=${hex(authorityId)}`);
