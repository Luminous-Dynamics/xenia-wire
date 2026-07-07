#!/usr/bin/env node
// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Independent (non-Rust) conformance checker for the xenia-wire envelope
// format, validating the "byte-deterministic across implementations" claim
// against the committed test vectors using only Node's built-in `crypto`
// (ChaCha20-Poly1305) -- no external dependencies, no xenia-wire code.
//
// For each envelope vector it does a *bidirectional* check:
//   1. open  -- AEAD-decrypt envelope[12..] under the fixed key with
//               nonce = envelope[0..12]; assert the plaintext equals the
//               vector's committed input.
//   2. seal  -- AEAD-encrypt that same input under the same key+nonce;
//               assert the produced envelope is byte-identical to the
//               committed envelope (this is the determinism proof -- a
//               conforming implementation MUST reproduce the exact bytes).
//   3. shape -- assert the nonce follows SPEC §3: source_id[0..6] constant
//               across all vectors, epoch byte == 0x42, length >= 28.
//
// Run:  node test-vectors/conformance/verify.mjs
// Exits non-zero if any vector fails.

import { createCipheriv, createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

// Fixed parameters shared by every vector (test-vectors/README.md).
const KEY = Buffer.from(
  "78656e69612d776972652d746573742d766563746f722d6b65792d3230323621",
  "hex",
);
const EPOCH_BYTE = 0x42;
const TAG_LEN = 16;
const NONCE_LEN = 12;

const PAYLOAD_TYPES = {
  FRAME: 0x10,
  INPUT: 0x11,
  FRAME_LZ4: 0x12,
  CONSENT_REQUEST: 0x20,
  CONSENT_RESPONSE: 0x21,
  CONSENT_REVOCATION: 0x22,
};

/** Parse a `.hex` fixture: 16 bytes/line, lowercase, `--`-comment lines and
 *  blank lines ignored. Returns a Buffer. */
function parseHex(relPath) {
  const text = readFileSync(join(VECTORS_DIR, relPath), "utf8");
  const hex = text
    .split("\n")
    .filter((line) => line.trim() !== "" && !line.trim().startsWith("--"))
    .join("")
    .replace(/\s+/g, "");
  return Buffer.from(hex, "hex");
}

/** Split a multi-envelope fixture on its `-- seq N --` markers. */
function parseEnvelopeGroups(relPath) {
  const text = readFileSync(join(VECTORS_DIR, relPath), "utf8");
  const groups = [];
  let current = null;
  for (const line of text.split("\n")) {
    if (line.trim().startsWith("--")) {
      if (current !== null) groups.push(current);
      current = "";
    } else if (line.trim() !== "" && current !== null) {
      current += line.trim();
    }
  }
  if (current) groups.push(current);
  return groups.map((h) => Buffer.from(h.replace(/\s+/g, ""), "hex"));
}

function open(envelope) {
  if (envelope.length < NONCE_LEN + TAG_LEN) {
    throw new Error(`envelope too short (${envelope.length} < 28 bytes)`);
  }
  const nonce = envelope.subarray(0, NONCE_LEN);
  const ct = envelope.subarray(NONCE_LEN, envelope.length - TAG_LEN);
  const tag = envelope.subarray(envelope.length - TAG_LEN);
  const decipher = createDecipheriv("chacha20-poly1305", KEY, nonce, {
    authTagLength: TAG_LEN,
  });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function seal(nonce, plaintext) {
  const cipher = createCipheriv("chacha20-poly1305", KEY, nonce, {
    authTagLength: TAG_LEN,
  });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
}

// ── Test harness ────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;
let sharedSourceId = null;

function check(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed += 1;
  } catch (e) {
    console.log(`  ✗ ${name}\n      ${e.message}`);
    failed += 1;
  }
}

function assertEqualBytes(actual, expected, what) {
  if (!Buffer.isBuffer(actual)) actual = Buffer.from(actual);
  if (!actual.equals(expected)) {
    throw new Error(
      `${what} mismatch:\n      got      ${actual.toString("hex")}\n` +
        `      expected ${expected.toString("hex")}`,
    );
  }
}

/** Full bidirectional + structural check for one single-envelope vector. */
function checkEnvelopeVector(name, plaintextPath, envelopePath, pldType) {
  const envelope = parseHex(envelopePath);
  const plaintext = parseHex(plaintextPath);
  const nonce = envelope.subarray(0, NONCE_LEN);

  // 1. open: decrypt reproduces the committed plaintext.
  assertEqualBytes(open(envelope), plaintext, "decrypted plaintext");

  // 2. seal: re-encrypting reproduces the committed envelope byte-for-byte.
  assertEqualBytes(seal(nonce, plaintext), envelope, "resealed envelope");

  // 3. nonce shape (SPEC §3).
  if (envelope[7] !== EPOCH_BYTE) {
    throw new Error(`epoch byte = 0x${envelope[7].toString(16)}, expected 0x42`);
  }
  if (pldType !== undefined && envelope[6] !== pldType) {
    throw new Error(
      `payload_type byte = 0x${envelope[6].toString(16)}, expected 0x${pldType.toString(16)}`,
    );
  }
  const srcId = envelope.subarray(0, 6);
  if (sharedSourceId === null) sharedSourceId = srcId;
  else assertEqualBytes(srcId, sharedSourceId, "source_id[0..6]");
}

console.log("xenia-wire envelope conformance (Node.js, native crypto)\n");

check("01 hello_frame  (FRAME, 12-byte payload)", () =>
  checkEnvelopeVector(
    "01",
    "01_hello_frame.input.hex",
    "01_hello_frame.envelope.hex",
    PAYLOAD_TYPES.FRAME,
  ),
);
check("02 input_pointer  (INPUT, domain separation)", () =>
  checkEnvelopeVector(
    "02",
    "02_input_pointer.input.hex",
    "02_input_pointer.envelope.hex",
    PAYLOAD_TYPES.INPUT,
  ),
);
check("03 empty_payload  (zero-length plaintext)", () =>
  checkEnvelopeVector(
    "03",
    "03_empty_payload.input.hex",
    "03_empty_payload.envelope.hex",
  ),
);
check("04 long_payload  (256-byte payload)", () =>
  checkEnvelopeVector(
    "04",
    "04_long_payload.input.hex",
    "04_long_payload.envelope.hex",
  ),
);

check("05 nonce_structure  (sequence 0,1,2 little-endian)", () => {
  const envelopes = parseEnvelopeGroups("05_nonce_structure.envelopes.hex");
  if (envelopes.length !== 3) {
    throw new Error(`expected 3 envelopes, got ${envelopes.length}`);
  }
  envelopes.forEach((env, i) => {
    open(env); // each must decrypt cleanly under the shared key
    const seq = env.readUInt32LE(8);
    if (seq !== i) throw new Error(`envelope ${i} has seq=${seq}, expected ${i}`);
    if (env[7] !== EPOCH_BYTE) throw new Error(`envelope ${i} epoch != 0x42`);
    // source_id, payload_type, epoch identical across the three.
    assertEqualBytes(
      env.subarray(0, 8),
      envelopes[0].subarray(0, 8),
      `envelope ${i} nonce prefix (bytes 0..8)`,
    );
  });
});

check("06 lz4_frame  (FRAME_LZ4, LZ4-before-AEAD)", () =>
  // The sealed plaintext is the LZ4-compressed payload; decrypt must
  // reproduce it, and reseal must reproduce the envelope. (We don't
  // reimplement LZ4 here -- the Rust vectors cover compress/decompress;
  // this validates the AEAD layer for the FRAME_LZ4 payload type.)
  checkEnvelopeVector(
    "06",
    "06_lz4_frame.lz4_compressed.hex",
    "06_lz4_frame.envelope.hex",
    PAYLOAD_TYPES.FRAME_LZ4,
  ),
);
check("07 consent_request  (CONSENT_REQUEST)", () =>
  checkEnvelopeVector(
    "07",
    "07_consent_request.input.hex",
    "07_consent_request.envelope.hex",
    PAYLOAD_TYPES.CONSENT_REQUEST,
  ),
);
check("08 consent_response  (CONSENT_RESPONSE)", () =>
  checkEnvelopeVector(
    "08",
    "08_consent_response.input.hex",
    "08_consent_response.envelope.hex",
    PAYLOAD_TYPES.CONSENT_RESPONSE,
  ),
);
check("09 consent_revocation  (CONSENT_REVOCATION)", () =>
  checkEnvelopeVector(
    "09",
    "09_consent_revocation.input.hex",
    "09_consent_revocation.envelope.hex",
    PAYLOAD_TYPES.CONSENT_REVOCATION,
  ),
);

// A tamper check: flipping one ciphertext byte must fail authentication,
// proving the Poly1305 tag is really being verified (not just parsed).
check("tamper rejection  (flipped byte fails AEAD auth)", () => {
  const env = Buffer.from(parseHex("01_hello_frame.envelope.hex"));
  env[NONCE_LEN + 1] ^= 0x01; // flip a ciphertext byte
  let rejected = false;
  try {
    open(env);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("tampered envelope was NOT rejected");
});

console.log(
  `\n${failed === 0 ? "✓ PASS" : "✗ FAIL"} — ${passed} passed, ${failed} failed`,
);
process.exit(failed === 0 ? 0 : 1);
