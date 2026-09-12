import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';

const hex = (value) => Buffer.from(value, 'hex');
const repeated = (byte) => Buffer.alloc(32, byte);
const u16le = (value) => {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
};
const u64le = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

// These inputs are intentionally reconstructed independently of the Rust code.
// They match src/attestation.rs's deterministic profile fixture.
const publicKey = hex('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c');
const expectedKeyId = hex('07dd40bed193b1146a3b0ae78d12efcda79542e6c5625cb12420ba3954a8b03e');
const expectedPreimageSha256 = hex('b435e9b459020a9689fa60743bbc665cf8ba153887eb33e5bb8cd18750dc0be3');
const signature = hex('34ceba6cd1dab8376350e095fbdeb9a2cb385483ea8593d1e2d1fa7a2d3c2569945ecc9910bdac55d697cb7366fa7c08a03364900b4f06a2e011a5b5cfc5090e');

const signatureProfile = 1;
const keyIdPreimage = Buffer.concat([
  Buffer.from('xenia.evidence-attestation.key-id.v1\0', 'ascii'),
  u16le(signatureProfile),
  publicKey,
]);
assert.deepEqual(sha256(keyIdPreimage), expectedKeyId, 'signer-key identity drifted');

const preimage = Buffer.concat([
  Buffer.from('xenia.evidence-attestation.v1\0', 'ascii'),
  u16le(1),                         // schema version
  repeated(0x11),                  // subject digest
  repeated(0x22),                  // context digest
  u16le(signatureProfile),
  expectedKeyId,
  u64le(1_700_000_000),            // issued_at
  u64le(1_700_003_600),            // valid_until
  repeated(0x33),                  // nonce
  Buffer.from([1]),                // Some(causal_binding)
  repeated(0x44),                  // causal binding
]);
assert.deepEqual(sha256(preimage), expectedPreimageSha256, 'canonical preimage drifted');

// RFC 8410 SubjectPublicKeyInfo prefix for a raw Ed25519 public key.
const spki = Buffer.concat([
  hex('302a300506032b6570032100'),
  publicKey,
]);
const verifierKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
assert.equal(verify(null, preimage, verifierKey, signature), true, 'Ed25519 signature did not verify');

// Cross-implementation hostile checks: modifying a signed semantic field must fail.
for (const [label, offset] of [
  ['schema', Buffer.from('xenia.evidence-attestation.v1\0', 'ascii').length],
  ['subject', Buffer.from('xenia.evidence-attestation.v1\0', 'ascii').length + 2],
  ['context', Buffer.from('xenia.evidence-attestation.v1\0', 'ascii').length + 2 + 32],
]) {
  const changed = Buffer.from(preimage);
  changed[offset] ^= 0x01;
  assert.equal(verify(null, changed, verifierKey, signature), false, `${label} mutation still verified`);
}

const changedSignature = Buffer.from(signature);
changedSignature[0] ^= 0x01;
assert.equal(verify(null, preimage, verifierKey, changedSignature), false, 'mutated signature still verified');

console.log('attestation conformance: canonical bytes, key ID, signature, and hostile mutations PASS');
