import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert/strict";

const fixture = JSON.parse(
  fs.readFileSync(new URL("../16_handshake_v2_contract.json", import.meta.url), "utf8"),
);

const maxEnvelope = fixture.transport.max_handshake_envelope_bytes;
const maxOffer = fixture.transport.max_capability_offer_bytes;
assert.equal(maxEnvelope, 16 * 1024);
assert.equal(maxOffer, 8 * 1024);

for (const [name, fixed] of Object.entries(fixture.candidate_bincode_fixed_bytes)) {
  const total = name === "host_finalize_v2" ? fixed : fixed + maxOffer;
  const headroomName = name.endsWith("_without_offer")
    ? name.slice(0, -"_without_offer".length)
    : name;
  assert.ok(total <= maxEnvelope, `${name} exceeds handshake envelope ceiling`);
  assert.equal(
    maxEnvelope - total,
    fixture.candidate_headroom_at_max_offer[headroomName],
    `${name} headroom drift`,
  );
}

assert.ok(
  fixture.candidate_headroom_at_max_offer.viewer_response_v2 >= 1024,
  "ViewerResponseV2 must retain at least 1 KiB envelope headroom",
);

const domain = Buffer.concat([
  Buffer.from("xenia.negotiated-session-context.v5", "utf8"),
  Buffer.from([0]),
]);
const baseV4 = Buffer.from(fixture.v5.base_v4_hash_hex, "hex");
const binding = Buffer.from(fixture.v5.negotiation_binding_hash_hex, "hex");
assert.equal(baseV4.length, 32);
assert.equal(binding.length, 32);

const preimage = Buffer.concat([domain, baseV4, binding]);
assert.equal(preimage.toString("hex"), fixture.v5.preimage_hex);
assert.equal(
  crypto.createHash("sha256").update(preimage).digest("hex"),
  fixture.v5.sha256,
);

console.log("handshake-v2 envelope budget + V5 context: PASS");
