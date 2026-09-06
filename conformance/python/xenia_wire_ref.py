#!/usr/bin/env python3
"""Independent Xenia wire conformance reference.

This module intentionally imports no xenia-wire/Rust bindings and uses only the
Python standard library. The ChaCha20-Poly1305 implementation follows RFC 8439
directly so published Xenia vectors are checked by an implementation with a
different language/runtime and no shared protocol helpers.

Scope v0.1:
- ChaCha20-Poly1305 seal/open with empty or supplied AAD
- Xenia 12-byte nonce/header parsing
- vectors 01-09 envelope compatibility where plaintext fixtures exist
- vector 05 nonce monotonicity
- draft-03 consent violation DSL vectors 10-12

It is a conformance oracle, not a production cryptography library.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import struct
from typing import Iterable

MASK32 = 0xFFFF_FFFF
FIXED_KEY = b"xenia-wire-test-vector-key-2026!"
FIXED_SOURCE_PREFIX = b"XENIAT"
FIXED_EPOCH = 0x42


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return one RFC 8439 ChaCha20 block."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be exactly 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be exactly 12 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("ChaCha20 counter outside u32 range")

    constants = b"expand 32-byte k"
    initial = list(
        struct.unpack("<4I", constants)
        + struct.unpack("<8I", key)
        + (counter,)
        + struct.unpack("<3I", nonce)
    )
    working = initial.copy()

    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    return struct.pack(
        "<16I",
        *((working[i] + initial[i]) & MASK32 for i in range(16)),
    )


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Encrypt/decrypt bytes using RFC 8439 ChaCha20."""
    out = bytearray()
    current = counter
    for offset in range(0, len(data), 64):
        if current > MASK32:
            raise ValueError("ChaCha20 counter exhausted")
        stream = chacha20_block(key, current, nonce)
        chunk = data[offset : offset + 64]
        out.extend(left ^ right for left, right in zip(chunk, stream))
        current += 1
    return bytes(out)


def _poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time key must be 32 bytes")

    r = int.from_bytes(one_time_key[:16], "little")
    r &= 0x0FFF_FFFC_0FFF_FFFC_0FFF_FFFC_0FFF_FFFF
    s = int.from_bytes(one_time_key[16:], "little")

    modulus = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        value = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + value) * r) % modulus

    return ((accumulator + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"" if remainder == 0 else b"\x00" * (16 - remainder)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """RFC 8439 ChaCha20-Poly1305 seal; returns ciphertext || 16-byte tag."""
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_input = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return ciphertext + _poly1305_mac(mac_input, poly_key)


def aead_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """RFC 8439 ChaCha20-Poly1305 open with constant-time tag comparison."""
    if len(sealed) < 16:
        raise ValueError("sealed payload shorter than Poly1305 tag")

    ciphertext, supplied_tag = sealed[:-16], sealed[-16:]
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_input = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    expected_tag = _poly1305_mac(mac_input, poly_key)
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError("ChaCha20-Poly1305 authentication failed")
    return chacha20_xor(key, nonce, ciphertext, counter=1)


@dataclass(frozen=True)
class XeniaNonce:
    source_prefix: bytes
    payload_type: int
    epoch: int
    sequence: int

    @classmethod
    def parse(cls, nonce: bytes) -> "XeniaNonce":
        if len(nonce) != 12:
            raise ValueError("Xenia nonce must be exactly 12 bytes")
        return cls(
            source_prefix=nonce[:6],
            payload_type=nonce[6],
            epoch=nonce[7],
            sequence=int.from_bytes(nonce[8:12], "little"),
        )

    def encode(self) -> bytes:
        if len(self.source_prefix) != 6:
            raise ValueError("source prefix must be six bytes")
        if not 0 <= self.payload_type <= 0xFF:
            raise ValueError("payload type outside u8 range")
        if not 0 <= self.epoch <= 0xFF:
            raise ValueError("epoch outside u8 range")
        if not 0 <= self.sequence <= MASK32:
            raise ValueError("sequence outside u32 range")
        return (
            self.source_prefix
            + bytes((self.payload_type, self.epoch))
            + self.sequence.to_bytes(4, "little")
        )


def read_hex(path: Path) -> bytes:
    text = "".join(path.read_text(encoding="utf-8").split())
    if len(text) % 2:
        raise ValueError(f"{path}: odd number of hex digits")
    try:
        return bytes.fromhex(text)
    except ValueError as error:
        raise ValueError(f"{path}: invalid hex fixture") from error


def _expected_plaintext_path(envelope_path: Path) -> Path:
    stem = envelope_path.name.removesuffix(".envelope.hex")
    if stem == "06_lz4_frame":
        candidate = envelope_path.with_name(stem + ".lz4_compressed.hex")
    else:
        candidate = envelope_path.with_name(stem + ".input.hex")
    if not candidate.is_file():
        raise FileNotFoundError(
            f"{envelope_path.name}: expected plaintext fixture {candidate.name}"
        )
    return candidate


@dataclass(frozen=True)
class ConsentViolation:
    variant: str
    request_id: int
    prior: bool | None = None
    new: bool | None = None


@dataclass
class ConsentMachine:
    """Minimal independent state model for frozen draft-03 vectors 10-12."""

    state: str = "AwaitingRequest"
    active_request_id: int | None = None
    approved: bool | None = None

    VALID_STATES = {
        "AwaitingRequest",
        "Requested",
        "Approved",
        "Denied",
        "Revoked",
    }

    def reset(self, state: str) -> None:
        if state not in self.VALID_STATES:
            raise ValueError(f"unknown consent state {state!r}")
        self.state = state
        self.active_request_id = None
        self.approved = True if state == "Approved" else False if state == "Denied" else None

    def observe(self, kind: str, request_id: int) -> ConsentViolation | None:
        before = (self.state, self.active_request_id, self.approved)

        if kind == "Request":
            self.state = "Requested"
            self.active_request_id = request_id
            self.approved = None
            return None

        if kind in {"ResponseApproved", "ResponseDenied"}:
            new_approved = kind == "ResponseApproved"
            if self.active_request_id != request_id:
                return ConsentViolation("StaleResponseForUnknownRequest", request_id)

            if self.state in {"Approved", "Denied"} and self.approved != new_approved:
                violation = ConsentViolation(
                    "ContradictoryResponse",
                    request_id,
                    prior=self.approved,
                    new=new_approved,
                )
                assert (self.state, self.active_request_id, self.approved) == before
                return violation

            if self.state == "Requested":
                self.state = "Approved" if new_approved else "Denied"
                self.approved = new_approved
                return None

            if self.state in {"Approved", "Denied"} and self.approved == new_approved:
                return None

            return ConsentViolation("StaleResponseForUnknownRequest", request_id)

        if kind == "Revocation":
            if self.state in {"AwaitingRequest", "Requested"}:
                violation = ConsentViolation("RevocationBeforeApproval", request_id)
                assert (self.state, self.active_request_id, self.approved) == before
                return violation
            if self.active_request_id != request_id:
                return ConsentViolation("StaleResponseForUnknownRequest", request_id)
            if self.state == "Approved":
                self.state = "Revoked"
                return None
            return ConsentViolation("RevocationBeforeApproval", request_id)

        raise ValueError(f"unknown consent event kind {kind!r}")


def _parse_bool(token: str) -> bool:
    if token == "true":
        return True
    if token == "false":
        return False
    raise ValueError(f"expected true/false, got {token!r}")


def run_consent_fixture(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index("---BEGIN---") + 1
    except ValueError as error:
        raise ValueError(f"{path}: missing ---BEGIN--- marker") from error

    machine = ConsentMachine()
    last_violation: ConsentViolation | None = None
    assertions = 0

    for raw in lines[start:]:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        parts = line.split()
        directive = parts[0]

        if directive == "INITIAL":
            if len(parts) != 2:
                raise ValueError(f"{path}: malformed INITIAL")
            machine.reset(parts[1])
            last_violation = None
            continue

        if directive == "EVENT":
            if len(parts) != 3:
                raise ValueError(f"{path}: malformed EVENT")
            last_violation = machine.observe(parts[1], int(parts[2]))
            continue

        if directive == "EXPECT_STATE":
            if len(parts) != 2:
                raise ValueError(f"{path}: malformed EXPECT_STATE")
            if machine.state != parts[1]:
                raise AssertionError(
                    f"{path}: expected state {parts[1]}, observed {machine.state}"
                )
            assertions += 1
            continue

        if directive == "EXPECT_VIOLATION":
            if len(parts) not in {3, 5}:
                raise ValueError(f"{path}: malformed EXPECT_VIOLATION")
            expected = ConsentViolation(
                parts[1],
                int(parts[2]),
                _parse_bool(parts[3]) if len(parts) == 5 else None,
                _parse_bool(parts[4]) if len(parts) == 5 else None,
            )
            if last_violation != expected:
                raise AssertionError(
                    f"{path}: expected violation {expected}, observed {last_violation}"
                )
            assertions += 1
            continue

        raise ValueError(f"{path}: unknown directive {directive!r}")

    return assertions


def parse_nonce_structure(path: Path) -> list[bytes]:
    envelopes: list[bytes] = []
    current: list[str] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("-- seq "):
            if current:
                envelopes.append(bytes.fromhex("".join(current)))
                current = []
            continue
        current.append(line)

    if current:
        envelopes.append(bytes.fromhex("".join(current)))
    return envelopes


def vector_digest(vector_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in vector_dir.iterdir() if p.is_file()):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def run_repository_conformance(repo_root: Path) -> dict[str, object]:
    vector_dir = repo_root / "test-vectors"
    spec_path = repo_root / "SPEC.md"
    if not vector_dir.is_dir() or not spec_path.is_file():
        raise FileNotFoundError("run from a xenia-wire checkout containing SPEC.md and test-vectors/")

    envelope_results: list[dict[str, object]] = []
    for envelope_path in sorted(vector_dir.glob("*.envelope.hex")):
        envelope = read_hex(envelope_path)
        if len(envelope) < 28:
            raise AssertionError(f"{envelope_path}: envelope shorter than nonce + tag")

        nonce_bytes = envelope[:12]
        nonce = XeniaNonce.parse(nonce_bytes)
        if nonce.encode() != nonce_bytes:
            raise AssertionError(f"{envelope_path}: nonce parse/encode instability")
        if nonce.source_prefix != FIXED_SOURCE_PREFIX:
            raise AssertionError(f"{envelope_path}: unexpected source prefix")
        if nonce.epoch != FIXED_EPOCH:
            raise AssertionError(f"{envelope_path}: unexpected epoch")
        if nonce.sequence != 0:
            raise AssertionError(f"{envelope_path}: envelope vector expected seq=0")

        expected_plaintext = read_hex(_expected_plaintext_path(envelope_path))
        opened = aead_open(FIXED_KEY, nonce_bytes, envelope[12:])
        if opened != expected_plaintext:
            raise AssertionError(f"{envelope_path}: plaintext mismatch")
        resealed = nonce_bytes + aead_seal(FIXED_KEY, nonce_bytes, opened)
        if resealed != envelope:
            raise AssertionError(f"{envelope_path}: independent reseal mismatch")

        envelope_results.append(
            {
                "vector": envelope_path.name,
                "payload_type": f"0x{nonce.payload_type:02x}",
                "plaintext_bytes": len(opened),
                "status": "pass",
            }
        )

    multi = parse_nonce_structure(vector_dir / "05_nonce_structure.envelopes.hex")
    sequences = [XeniaNonce.parse(item[:12]).sequence for item in multi]
    if sequences != [0, 1, 2]:
        raise AssertionError(f"vector 05: expected nonce sequences [0, 1, 2], got {sequences}")
    nonce_prefixes = [item[:8] for item in multi]
    if len(set(nonce_prefixes)) != 1:
        raise AssertionError("vector 05: source/type/epoch prefix changed across sequence")

    consent_results: list[dict[str, object]] = []
    for name in (
        "10_revocation_before_approval.txt",
        "11_contradictory_response.txt",
        "12_stale_response.txt",
    ):
        assertions = run_consent_fixture(vector_dir / name)
        consent_results.append(
            {"vector": name, "assertions": assertions, "status": "pass"}
        )

    return {
        "schema": "xenia-wire-independent-conformance-v0.1",
        "implementation": "python-stdlib-rfc8439",
        "claim_boundary": "independent fixture conformance; not production readiness or external audit",
        "spec": {
            "path": "SPEC.md",
            "sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        },
        "vectors": {
            "tree_sha256": vector_digest(vector_dir),
            "envelope": envelope_results,
            "nonce_structure": {"sequences": sequences, "status": "pass"},
            "consent": consent_results,
        },
    }


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit deterministic machine-readable conformance report",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    report = run_repository_conformance(_repo_root())
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        envelope_count = len(report["vectors"]["envelope"])  # type: ignore[index]
        consent_count = len(report["vectors"]["consent"])  # type: ignore[index]
        print(
            "PASS: independent Python conformance "
            f"({envelope_count} envelope vectors, vector 05 nonce sequence, "
            f"{consent_count} consent DSL fixtures)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
