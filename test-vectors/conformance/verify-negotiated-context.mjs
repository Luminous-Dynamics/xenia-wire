import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert/strict";

const fixture = JSON.parse(
  fs.readFileSync(new URL("../14_negotiated_context_v1.json", import.meta.url), "utf8"),
);

assert.equal(fixture.hash_algorithm, "sha256");

const DOMAIN = Buffer.concat([
  Buffer.from("xenia.negotiated-context.v1", "utf8"),
  Buffer.from([0]),
]);

function u16be(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function u32be(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function compareCapability(a, b) {
  const byName = Buffer.compare(a.name, b.name);
  if (byName !== 0) return byName;
  return Buffer.compare(a.version, b.version);
}

function canonicalize(capabilities) {
  assert.ok(capabilities.length <= 64, "too many capabilities");

  const normalized = capabilities.map((entry) => {
    const name = Buffer.from(entry.name_utf8, "utf8");
    const version = Buffer.from(entry.version_utf8, "utf8");
    assert.ok(name.length > 0 && name.length <= 128, "invalid capability name length");
    assert.ok(version.length > 0 && version.length <= 32, "invalid capability version length");
    return { name, version };
  });

  normalized.sort(compareCapability);
  for (let i = 1; i < normalized.length; i += 1) {
    assert.notEqual(
      compareCapability(normalized[i - 1], normalized[i]),
      0,
      "duplicate capability must fail closed",
    );
  }

  const chunks = [DOMAIN, u32be(normalized.length)];
  for (const capability of normalized) {
    chunks.push(u16be(capability.name.length), capability.name);
    chunks.push(u16be(capability.version.length), capability.version);
  }
  return Buffer.concat(chunks);
}

for (const vector of fixture.vectors) {
  const canonical = canonicalize(vector.capabilities);
  assert.equal(canonical.toString("hex"), vector.canonical_hex, `${vector.name}: canonical bytes`);
  const digest = crypto.createHash("sha256").update(canonical).digest("hex");
  assert.equal(digest, vector.sha256, `${vector.name}: SHA-256`);
  console.log(`${vector.name}: ${digest}`);
}

// The selected-set hash must be independent of advertisement order.
const pair = fixture.vectors.find((vector) => vector.name === "causal-authority-plus-operator-rekey");
assert.ok(pair);
const reversed = canonicalize([...pair.capabilities].reverse());
assert.equal(reversed.toString("hex"), pair.canonical_hex, "capability order changed canonical bytes");

// Exact version bytes are load-bearing.
const authorityOnly = fixture.vectors.find((vector) => vector.name === "causal-authority-draft04-only");
assert.ok(authorityOnly);
const downgraded = canonicalize([
  { name_utf8: "xenia.causal-authority", version_utf8: "draft-03" },
]);
const downgradedDigest = crypto.createHash("sha256").update(downgraded).digest("hex");
assert.notEqual(downgradedDigest, authorityOnly.sha256, "draft-03 must not collide with draft-04");

console.log("negotiated-context-v1 conformance: PASS");
