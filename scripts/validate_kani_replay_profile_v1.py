#!/usr/bin/env python3
"""Validate the candidate bounded Kani profile for xenia-wire ReplayWindow."""

from __future__ import annotations

import copy
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = ROOT / "formal/kani/replay_window_profile_v1.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")

EXPECTED_OBLIGATIONS = {
    "AdmittedWidthGeometrySafe",
    "FirstSequenceInitializesSafely",
    "ImmediateDuplicateRejected",
    "InWindowDuplicateRejected",
    "TooOldRejected",
    "UnseenInWindowAcceptedOnce",
    "ForwardHighestMonotonicWithinStream",
    "BitmapIndexInBounds",
    "UnsignedSubtractionBranchSafe",
    "ShiftWidthSafe",
    "LargeJumpClearsAndSeeds",
    "StreamKeyIsolation",
    "DropEpochIsolation",
    "ShiftBitmapReferenceEquivalenceBounded",
}
EXPECTED_MAPPING = {
    "all_selected_harnesses_verified_with_sufficient_bounds": "Pass",
    "property_counterexample_or_reachable_safety_failure": "Fail",
    "insufficient_unwind_or_unsupported_required_semantics": "Blocked",
    "tool_setup_or_executor_failure": "EnvironmentFailure",
}

class ContractError(ValueError):
    pass


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise ContractError(msg)


def validate(p: dict) -> None:
    require(p.get("schema") == "xenia.formal.kani.replay-window-profile.v1", "schema drift")
    require(p.get("tracking_issue") == 70, "tracking issue drift")
    require(p.get("authority") == "EvidenceOnly", "authority escalation")
    require(p.get("status") == "CandidateProfileNeedsQualification", "candidate profile may not self-promote")
    require(p.get("evidence_class") == "BoundedModelSafety", "evidence class drift")

    subject = p.get("subject", {})
    require(subject.get("repository") == "Luminous-Dynamics/xenia-wire", "subject repository drift")
    require(subject.get("commit") == "057dd03043b8863d8f8280abf333331cc9ddf317", "subject commit drift")
    require(subject.get("path") == "src/replay_window.rs", "subject path drift")
    require(subject.get("blob") == "9e55ddf7bfd7d7851cc3968d3407bd2c78ba9908", "subject blob drift")
    require(HEX40.fullmatch(subject.get("commit", "")) is not None, "subject commit must be 40-hex")
    require(HEX40.fullmatch(subject.get("blob", "")) is not None, "subject blob must be 40-hex")

    tool = p.get("tool", {})
    require(tool.get("name") == "Kani", "tool drift")
    require(tool.get("version") == "0.67.0", "Kani version drift")
    require(tool.get("upstream_repository") == "model-checking/kani", "Kani repo drift")
    require(tool.get("upstream_commit") == "4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d", "Kani commit drift")
    require(HEX40.fullmatch(tool.get("upstream_commit", "")) is not None, "Kani upstream pin must be 40-hex")
    rule = tool.get("installation_rule", "").lower()
    require("no latest" in rule and "moving refs" in rule, "moving-install prohibition required")

    bounds = p.get("bounds", {})
    require(bounds.get("window_width_bits") == [64, 128], "V1 width profile drift")
    require(bounds.get("max_trace_steps") == 4, "V1 trace bound drift")
    require(bounds.get("max_distinct_stream_keys") == 2, "V1 stream bound drift")
    require(bounds.get("sequence_values") == "symbolic u64 per step", "sequence domain drift")
    require("failed unwinding assertion blocks PASS" in bounds.get("unwind_policy", ""), "unwind admission rule required")

    strategy = p.get("implementation_strategy", {})
    require(strategy.get("first") == "DirectProductionPath", "direct production path must be attempted first")
    require(strategy.get("fallback") == "ProductionPureTransitionKernelSeam", "fallback seam identity drift")
    rule = strategy.get("fallback_rule", "")
    require("production-used" in rule and "not a verification-only copy" in rule, "verification-only duplicate forbidden")

    require(set(p.get("obligations", [])) == EXPECTED_OBLIGATIONS, "proof obligation census drift")

    boundary = p.get("constructor_boundary", {})
    require(boundary.get("admitted_width_precondition") == "64 <= bits <= 1024 && bits % 64 == 0", "constructor precondition drift")
    require(boundary.get("invalid_width_panic_is_expected") is True, "invalid-width panic must remain explicit")
    require(boundary.get("universal_panic_freedom_claim_forbidden") is True, "universal panic-free claim must remain forbidden")

    require(p.get("canonical_result_mapping") == EXPECTED_MAPPING, "canonical result mapping drift")

    fields = set(p.get("required_receipt_fields", []))
    for required in {
        "source_commit", "source_tree", "source_blob", "harness_blob",
        "kani_version", "kani_upstream_commit", "exact_bounds",
        "exact_command_line", "harness_results", "unwinding_results",
        "full_output_digest", "repository_postflight_clean",
    }:
        require(required in fields, f"required receipt field missing: {required}")

    ceiling = "\n".join(p.get("claim_ceiling", [])).lower()
    for phrase in (
        "bounded replay-window implementation safety",
        "not an unbounded replay theorem",
        "not cryptographic authenticity",
        "not compiler or native-binary correctness",
        "not cross-repository proof portability",
    ):
        require(phrase in ceiling, f"claim ceiling missing: {phrase}")

    nonclaims = set(p.get("nonclaims", []))
    for required in {
        "KaniHarnessesImplemented", "KaniExecutionQualified", "UnboundedReplayCorrectness",
        "VerusDeductiveProof", "CompilerCorrectness", "RuntimeAuthority",
    }:
        require(required in nonclaims, f"required nonclaim missing: {required}")


def expect_reject(name: str, p: dict) -> None:
    try:
        validate(p)
    except ContractError:
        return
    raise AssertionError(f"hostile mutant unexpectedly accepted: {name}")


def self_test(p: dict) -> None:
    m = copy.deepcopy(p)
    m["tool"]["version"] = "latest"
    expect_reject("moving-tool-version", m)

    m = copy.deepcopy(p)
    m["tool"]["upstream_commit"] = "main"
    expect_reject("moving-upstream-ref", m)

    m = copy.deepcopy(p)
    m["bounds"]["max_trace_steps"] = 2
    expect_reject("silent-trace-bound-reduction", m)

    m = copy.deepcopy(p)
    m["bounds"]["window_width_bits"] = [64]
    expect_reject("silent-width-profile-reduction", m)

    m = copy.deepcopy(p)
    m["canonical_result_mapping"]["insufficient_unwind_or_unsupported_required_semantics"] = "Pass"
    expect_reject("insufficient-unwind-promoted", m)

    m = copy.deepcopy(p)
    m["constructor_boundary"]["universal_panic_freedom_claim_forbidden"] = False
    expect_reject("invalid-width-panic-hidden", m)

    m = copy.deepcopy(p)
    m["implementation_strategy"]["fallback_rule"] = "verification-only copied algorithm"
    expect_reject("verification-copy-admitted", m)

    m = copy.deepcopy(p)
    m["subject"]["blob"] = "0" * 40
    expect_reject("source-blob-rebind", m)


def main() -> int:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    validate(profile)
    self_test(profile)
    print("xen_fv_kani_replay_profile_v1=PASS")
    print("profile_status=CandidateProfileNeedsQualification")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"xen_fv_kani_replay_profile_v1=FAIL: {exc}", file=sys.stderr)
        raise
