#!/usr/bin/env python3
"""Tests for the independent Python Xenia conformance implementation."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import xenia_wire_ref as ref  # noqa: E402


class Rfc8439Tests(unittest.TestCase):
    """Anchor the independent crypto implementation to RFC 8439, not Rust."""

    def test_aead_known_answer_vector(self) -> None:
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        )
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = bytes.fromhex(
            "4c616469657320616e642047656e746c"
            "656d656e206f662074686520636c6173"
            "73206f66202739393a20496620492063"
            "6f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220"
            "746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069"
            "742e"
        )
        expected = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b3"
            "692ddbd7f2d778b8c9803aee328091b5"
            "8fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
            "1ae10b594f09e26a7e902ecbd0600691"
        )

        sealed = ref.aead_seal(key, nonce, plaintext, aad)
        self.assertEqual(sealed, expected)
        self.assertEqual(ref.aead_open(key, nonce, sealed, aad), plaintext)

    def test_modified_tag_is_rejected(self) -> None:
        nonce = bytes.fromhex("000000000000000000000000")
        sealed = bytearray(ref.aead_seal(bytes(32), nonce, b"authenticated"))
        sealed[-1] ^= 0x01
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            ref.aead_open(bytes(32), nonce, bytes(sealed))


class RepositoryVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = HERE.parents[1]
        cls.report = ref.run_repository_conformance(cls.repo_root)

    def test_all_available_envelope_vectors_pass(self) -> None:
        envelope = self.report["vectors"]["envelope"]
        self.assertGreaterEqual(len(envelope), 8)
        self.assertTrue(all(item["status"] == "pass" for item in envelope))

    def test_nonce_structure_is_exactly_monotonic(self) -> None:
        nonce = self.report["vectors"]["nonce_structure"]
        self.assertEqual(nonce["sequences"], [0, 1, 2])
        self.assertEqual(nonce["status"], "pass")

    def test_all_frozen_consent_dsl_vectors_pass(self) -> None:
        consent = self.report["vectors"]["consent"]
        self.assertEqual(len(consent), 3)
        self.assertTrue(all(item["status"] == "pass" for item in consent))
        self.assertTrue(all(item["assertions"] > 0 for item in consent))

    def test_report_is_json_serializable_and_stable(self) -> None:
        first = json.dumps(self.report, sort_keys=True, separators=(",", ":"))
        second = json.dumps(
            ref.run_repository_conformance(self.repo_root),
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(first, second)

    def test_reference_has_no_rust_or_native_bridge_dependency(self) -> None:
        source = (HERE / "xenia_wire_ref.py").read_text(encoding="utf-8")
        forbidden = (
            "import subprocess",
            "from subprocess",
            "import ctypes",
            "from ctypes",
            "import cffi",
            "from cffi",
            "import xenia_wire",
            "from xenia_wire",
            "cargo run",
            "cargo test",
        )
        for needle in forbidden:
            self.assertNotIn(needle, source, needle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
