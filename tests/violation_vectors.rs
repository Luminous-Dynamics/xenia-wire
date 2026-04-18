// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Executable runner for the consent-violation test vectors
//! (10/11/12 under `test-vectors/`).
//!
//! The vector files use a tiny line-oriented DSL (documented inline
//! in `10_revocation_before_approval.txt`) so that an alternate-
//! language implementation can write a parallel runner from scratch
//! without depending on this crate's types. This test exercises the
//! Rust reference implementation against the same fixtures.

#![cfg(all(feature = "consent", feature = "reference-frame"))]

use std::fs;
use std::path::Path;
use xenia_wire::consent::{ConsentEvent, ConsentState, ConsentViolation};
use xenia_wire::Session;

#[derive(Debug)]
enum Line {
    Initial(ConsentState),
    Event(ConsentEvent),
    ExpectState(ConsentState),
    ExpectViolation(ExpectedViolation),
}

#[derive(Debug)]
struct ExpectedViolation {
    variant: &'static str,
    request_id: u64,
    prior: Option<bool>,
    new: Option<bool>,
}

fn parse_state(s: &str) -> ConsentState {
    match s {
        "LegacyBypass" => ConsentState::LegacyBypass,
        "AwaitingRequest" => ConsentState::AwaitingRequest,
        "Requested" => ConsentState::Requested,
        "Approved" => ConsentState::Approved,
        "Denied" => ConsentState::Denied,
        "Revoked" => ConsentState::Revoked,
        other => panic!("unknown ConsentState: {other}"),
    }
}

fn parse_event(kind: &str, request_id: u64) -> ConsentEvent {
    match kind {
        "Request" => ConsentEvent::Request { request_id },
        "ResponseApproved" => ConsentEvent::ResponseApproved { request_id },
        "ResponseDenied" => ConsentEvent::ResponseDenied { request_id },
        "Revocation" => ConsentEvent::Revocation { request_id },
        other => panic!("unknown ConsentEvent kind: {other}"),
    }
}

fn parse_bool(s: &str) -> bool {
    match s {
        "true" => true,
        "false" => false,
        other => panic!("expected true/false, got: {other}"),
    }
}

fn parse_vector(text: &str) -> Vec<Line> {
    let mut out = Vec::new();
    // Skip all lines until the explicit BEGIN marker so documentation
    // prose can use keyword names freely without confusing the parser.
    let mut in_vector = false;
    for raw in text.lines() {
        let line = raw.trim();
        if !in_vector {
            if line == "---BEGIN---" {
                in_vector = true;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line == "---END---" {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "INITIAL" => {
                assert_eq!(parts.len(), 2, "INITIAL takes one argument: {line}");
                out.push(Line::Initial(parse_state(parts[1])));
            }
            "EVENT" => {
                assert_eq!(parts.len(), 3, "EVENT takes two args: kind, request_id: {line}");
                let id = parts[2].parse::<u64>().expect("request_id is u64");
                out.push(Line::Event(parse_event(parts[1], id)));
            }
            "EXPECT_STATE" => {
                assert_eq!(parts.len(), 2, "EXPECT_STATE takes one argument: {line}");
                out.push(Line::ExpectState(parse_state(parts[1])));
            }
            "EXPECT_VIOLATION" => {
                // RevocationBeforeApproval <id>                -> 3 parts
                // ContradictoryResponse <id> <prior> <new>      -> 5 parts
                // StaleResponseForUnknownRequest <id>           -> 3 parts
                let id = parts[2].parse::<u64>().expect("request_id is u64");
                let expected = match parts[1] {
                    "RevocationBeforeApproval" => {
                        assert_eq!(parts.len(), 3);
                        ExpectedViolation {
                            variant: "RevocationBeforeApproval",
                            request_id: id,
                            prior: None,
                            new: None,
                        }
                    }
                    "StaleResponseForUnknownRequest" => {
                        assert_eq!(parts.len(), 3);
                        ExpectedViolation {
                            variant: "StaleResponseForUnknownRequest",
                            request_id: id,
                            prior: None,
                            new: None,
                        }
                    }
                    "ContradictoryResponse" => {
                        assert_eq!(
                            parts.len(),
                            5,
                            "ContradictoryResponse requires prior + new: {line}"
                        );
                        ExpectedViolation {
                            variant: "ContradictoryResponse",
                            request_id: id,
                            prior: Some(parse_bool(parts[3])),
                            new: Some(parse_bool(parts[4])),
                        }
                    }
                    other => panic!("unknown ConsentViolation variant: {other}"),
                };
                out.push(Line::ExpectViolation(expected));
            }
            other => panic!("internal: unhandled keyword {other}"),
        }
    }
    out
}

fn run_vector(path: &Path) {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let script = parse_vector(&text);

    // Initial state sets the builder config: AwaitingRequest = ceremony mode,
    // LegacyBypass = default. (The other variants can't be start states, but
    // we allow the DSL to name them for documentation.)
    let initial = match script.first() {
        Some(Line::Initial(s)) => *s,
        _ => panic!("{}: must start with INITIAL", path.display()),
    };
    let mut session = match initial {
        ConsentState::AwaitingRequest => {
            Session::builder().require_consent(true).build()
        }
        ConsentState::LegacyBypass => Session::new(),
        other => panic!(
            "{}: INITIAL state {:?} cannot be a fresh-session start state",
            path.display(),
            other
        ),
    };
    session.install_key([0x42; 32]);
    assert_eq!(
        session.consent_state(),
        initial,
        "{}: session did not start in declared initial state",
        path.display()
    );

    // Walk the rest, tracking the "last event's result" so that
    // EXPECT_STATE and EXPECT_VIOLATION can assert on it.
    let mut last_result: Option<Result<ConsentState, ConsentViolation>> = None;
    for line in script.iter().skip(1) {
        match line {
            Line::Initial(_) => panic!("{}: INITIAL appears twice", path.display()),
            Line::Event(ev) => {
                last_result = Some(session.observe_consent(*ev));
            }
            Line::ExpectState(expected) => {
                assert_eq!(
                    session.consent_state(),
                    *expected,
                    "{}: EXPECT_STATE mismatch after {:?}",
                    path.display(),
                    line
                );
            }
            Line::ExpectViolation(expected) => {
                let got = last_result
                    .as_ref()
                    .expect("EXPECT_VIOLATION before any EVENT");
                let violation = match got {
                    Err(v) => v,
                    Ok(state) => panic!(
                        "{}: expected violation {:?} but got Ok({:?})",
                        path.display(),
                        expected,
                        state
                    ),
                };
                match (expected.variant, violation) {
                    (
                        "RevocationBeforeApproval",
                        ConsentViolation::RevocationBeforeApproval { request_id },
                    ) => {
                        assert_eq!(*request_id, expected.request_id);
                    }
                    (
                        "StaleResponseForUnknownRequest",
                        ConsentViolation::StaleResponseForUnknownRequest { request_id },
                    ) => {
                        assert_eq!(*request_id, expected.request_id);
                    }
                    (
                        "ContradictoryResponse",
                        ConsentViolation::ContradictoryResponse {
                            request_id,
                            prior_approved,
                            new_approved,
                        },
                    ) => {
                        assert_eq!(*request_id, expected.request_id);
                        assert_eq!(Some(*prior_approved), expected.prior);
                        assert_eq!(Some(*new_approved), expected.new);
                    }
                    (variant, actual) => panic!(
                        "{}: expected violation {} but got {:?}",
                        path.display(),
                        variant,
                        actual
                    ),
                }
            }
        }
    }
}

fn vectors_dir() -> &'static Path {
    Path::new("test-vectors")
}

#[test]
fn vector_10_revocation_before_approval() {
    run_vector(&vectors_dir().join("10_revocation_before_approval.txt"));
}

#[test]
fn vector_11_contradictory_response() {
    run_vector(&vectors_dir().join("11_contradictory_response.txt"));
}

#[test]
fn vector_12_stale_response() {
    run_vector(&vectors_dir().join("12_stale_response.txt"));
}
