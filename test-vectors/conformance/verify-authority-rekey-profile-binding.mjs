import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vector = JSON.parse(
  readFileSync(new URL("../19_authority_rekey_profile_binding_v1.json", import.meta.url), "utf8"),
);

const domain = Buffer.from("xenia.authority-rekey-profile-binding.v1\0", "utf8");
const lineage = Buffer.from(vector.lineage_id_hex, "hex");
const activation = Buffer.from(vector.activation_id_hex, "hex");

if (lineage.length !== 32 || activation.length !== 32) {
  throw new Error("binding vector identifiers must be 32 bytes");
}

function bindingId(profileCode) {
  return createHash("sha256")
    .update(domain)
    .update(lineage)
    .update(activation)
    .update(Buffer.from([profileCode]))
    .digest("hex");
}

for (const [name, profile] of Object.entries(vector.profiles)) {
  const actual = bindingId(profile.code);
  if (actual !== profile.binding_id_sha256_hex) {
    throw new Error(`${name}: binding id mismatch: ${actual}`);
  }
}

if (
  vector.profiles.lane_session_v1.binding_id_sha256_hex ===
  vector.profiles.operator_channel_v1.binding_id_sha256_hex
) {
  throw new Error("distinct rekey profiles must not share a binding id");
}

if (
  vector.profiles.operator_channel_v1.required_capability_name_utf8 !==
    "xenia.operator-rekey" ||
  vector.profiles.operator_channel_v1.required_capability_version_utf8 !== "v1"
) {
  throw new Error("operator rekey exact capability identity drifted");
}

console.log("PASS: independently reproduced authority rekey profile binding vectors");
