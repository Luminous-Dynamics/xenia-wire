#!/usr/bin/env python3
"""Construct the formatter/Clippy-clean #44 current-key receive successor.

The constructor is intentionally read-only with respect to reviewed runtime
history: it starts from the exact qualified #34/#52 composed parent, proves the
historical #44 parent differs in Session only by the known #37 guard spelling,
then transplants the exact historical #44 five-file semantic delta while
preserving the final #37 duplicate-install repair byte semantics.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

BASE_SHA = "adccf0fb65365ff492a4529bd209ca6bc846e5f0"
BASE_TREE = "890df767447cd7aeb7c4cc0e531840c8f9a292bb"
HISTORICAL_PARENT = "0ad16f308638a378b851ffc461219af62e1135f0"
HISTORICAL_HEAD = "d13f203caeb46497490527c39bfec567f7902e60"

SESSION_PATH = "src/session.rs"
REUSED_PATHS = (
    ".github/workflows/nonce-safety.yml",
    "src/lib.rs",
    "src/strict_receive.rs",
)
NEW_TEST_PATH = "tests/current_key_open.rs"
EXPECTED_CHANGED = sorted((*REUSED_PATHS, SESSION_PATH, NEW_TEST_PATH))

EXPECTED_BASE_BLOBS = {
    ".github/workflows/nonce-safety.yml": "24c88f6827d533d7dfbfa240c116ecb569ac91e1",
    "src/lib.rs": "b90a8f255270d8a4e347d23016647b7f5f134e51",
    "src/strict_receive.rs": "d335b01e381ad987b441ccfdc199564a7d1538ce",
    "src/session.rs": "2b80a1c9e13de4772147f38eb2c936b31ff01165",
}
EXPECTED_HISTORICAL_OUTPUT_BLOBS = {
    ".github/workflows/nonce-safety.yml": "7deb602022e36b5aeee431e8152f9f59bb6ad7eb",
    "src/lib.rs": "f3043cba8dbac6fcf0cd1621dca28373022487a6",
    "src/strict_receive.rs": "5aebac3b70caac40b201cf11c65e0dcb534631e8",
    "src/session.rs": "63cfec0d36d1f3fe99800592d49e9e101fb536af",
    "tests/current_key_open.rs": "026efd7575e8d83414fe3f5cd9ddaae799e2f64c",
}

OLD_GUARD = b"""        if let Some(current_key) = self.session_key.as_ref() {\n            if ct_eq_32(&**current_key, &key) {\n                return;\n            }\n        }\n"""
NEW_GUARD = b"""        if let Some(current_key) = self.session_key.as_ref()\n            && ct_eq_32(current_key, &key)\n        {\n            return;\n        }\n"""


def git(*args: str, text: bool = True):
    return subprocess.check_output(["git", *args], text=text)


def blob_sha(ref: str, path: str) -> str:
    return git("rev-parse", f"{ref}:{path}").strip()


def show_bytes(ref: str, path: str) -> bytes:
    return git("show", f"{ref}:{path}", text=False)


def assert_commit(ref: str) -> None:
    subprocess.run(["git", "cat-file", "-e", f"{ref}^{{commit}}"], check=True)


def replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected guard exactly once, found {count}")
    return data.replace(old, new, 1)


def main() -> None:
    for ref in (BASE_SHA, HISTORICAL_PARENT, HISTORICAL_HEAD):
        assert_commit(ref)

    if git("rev-parse", f"{BASE_SHA}^{{tree}}").strip() != BASE_TREE:
        raise SystemExit("exact base tree changed")

    # The constructor branch may carry tooling files, but every production input
    # must still be byte-identical to the exact qualified base.
    for path, expected in EXPECTED_BASE_BLOBS.items():
        if blob_sha(BASE_SHA, path) != expected:
            raise SystemExit(f"unexpected base blob for {path}")
        if Path(path).read_bytes() != show_bytes(BASE_SHA, path):
            raise SystemExit(f"constructor branch modified production input {path}")

    # Prove the three non-Session parent files are literally identical between
    # the historical #44 parent and the qualified current parent. This is what
    # makes exact historical-result blob transplantation safe for those files.
    for path in REUSED_PATHS:
        if show_bytes(HISTORICAL_PARENT, path) != show_bytes(BASE_SHA, path):
            raise SystemExit(f"parent drift outside Session for {path}")
        expected_output = EXPECTED_HISTORICAL_OUTPUT_BLOBS[path]
        if blob_sha(HISTORICAL_HEAD, path) != expected_output:
            raise SystemExit(f"historical output blob changed for {path}")

    # Prove the complete Session parent drift is *only* #37's final stable-
    # Clippy let-chain spelling. No other production change may be silently
    # absorbed by this reconstruction.
    historical_parent_session = show_bytes(HISTORICAL_PARENT, SESSION_PATH)
    current_base_session = show_bytes(BASE_SHA, SESSION_PATH)
    normalized_historical_parent = replace_once(
        historical_parent_session,
        OLD_GUARD,
        NEW_GUARD,
        "historical parent Session",
    )
    if normalized_historical_parent != current_base_session:
        raise SystemExit(
            "Session parent drift is wider than the single admitted #37 guard normalization"
        )

    if blob_sha(HISTORICAL_HEAD, SESSION_PATH) != EXPECTED_HISTORICAL_OUTPUT_BLOBS[SESSION_PATH]:
        raise SystemExit("historical #44 Session blob changed")
    if blob_sha(HISTORICAL_HEAD, NEW_TEST_PATH) != EXPECTED_HISTORICAL_OUTPUT_BLOBS[NEW_TEST_PATH]:
        raise SystemExit("historical #44 current-key test blob changed")

    # Transplant the exact historical #44 outputs where parents were proven
    # identical. The new test did not exist on the base.
    for path in REUSED_PATHS:
        Path(path).write_bytes(show_bytes(HISTORICAL_HEAD, path))
    try:
        subprocess.run(
            ["git", "cat-file", "-e", f"{BASE_SHA}:{NEW_TEST_PATH}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        pass
    else:
        raise SystemExit(f"{NEW_TEST_PATH} unexpectedly exists on base")
    Path(NEW_TEST_PATH).write_bytes(show_bytes(HISTORICAL_HEAD, NEW_TEST_PATH))

    # Merge #44's tested Session result with the one exact #37 normalization.
    historical_head_session = show_bytes(HISTORICAL_HEAD, SESSION_PATH)
    merged_session = replace_once(
        historical_head_session,
        OLD_GUARD,
        NEW_GUARD,
        "historical #44 Session",
    )
    Path(SESSION_PATH).write_bytes(merged_session)

    changed = sorted(git("diff", "--name-only").splitlines())
    if changed != EXPECTED_CHANGED:
        raise SystemExit(f"unexpected runtime delta: {changed}")

    # Structural guardrails for the intended current-key receive surface.
    session = Path(SESSION_PATH).read_text()
    strict = Path("src/strict_receive.rs").read_text()
    lib = Path("src/lib.rs").read_text()
    workflow = Path(".github/workflows/nonce-safety.yml").read_text()
    tests = Path(NEW_TEST_PATH).read_text()

    required = (
        "pub(crate) fn open_current_key",
        "fn split_envelope",
        "fn finish_open",
        "&& ct_eq_32(current_key, &key)",
        "open_current_key_from_nonce_domain",
        "previous_key_rejects_before_current_epoch_replay_mutation",
        "ordinary_open_still_accepts_previous_key_during_grace",
    )
    combined = "\n".join((session, strict, lib, workflow, tests))
    for marker in required:
        if marker not in combined:
            raise SystemExit(f"missing required reconstruction marker: {marker}")

    if '"tests/current_key_open.rs"' not in workflow:
        raise SystemExit("nonce-safety workflow does not watch current_key_open.rs")

    print("current-key receive r1 reconstruction complete")
    print(f"base={BASE_SHA}")
    print(f"historical_parent={HISTORICAL_PARENT}")
    print(f"historical_head={HISTORICAL_HEAD}")
    for path in EXPECTED_CHANGED:
        print(f"changed_file={path}")


if __name__ == "__main__":
    main()
