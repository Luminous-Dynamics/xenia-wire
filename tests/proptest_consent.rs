// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Property tests for the consent state machine (SPEC draft-03).
//!
//! Fuzzes arbitrary sequences of [`ConsentEvent`]s (each with a
//! bounded `request_id`) into a session and asserts:
//!
//! - Terminal states (`Denied`, `Revoked`) are NOT absolute — a higher
//!   `request_id` can start a fresh ceremony. What stays absolute is
//!   that without such an escalation, the state does not spontaneously
//!   leave the terminal variant.
//! - `can_seal_frame` decisions match the SPEC §12.7 rules for the
//!   current state.
//! - `ConsentState::LegacyBypass` and `ConsentState::Approved` are the
//!   only states where application FRAME seals succeed.
//! - `observe_consent` never panics, and the session state is a
//!   valid enum variant after any event sequence.

#![cfg(all(feature = "consent", feature = "reference-frame"))]

use proptest::prelude::*;
use xenia_wire::consent::{ConsentEvent, ConsentState};
use xenia_wire::{seal_frame, Frame, Session, WireError};

fn session_with_key() -> Session {
    let mut s = Session::builder().require_consent(true).build();
    s.install_key([0x42; 32]);
    s
}

fn any_event() -> impl Strategy<Value = ConsentEvent> {
    // request_id bounded to [0, 5] so we stress the id-driven
    // transition branches (replacements, stale, match/mismatch)
    // rather than sparsely hitting a uniform u64 space.
    (0u64..=5).prop_flat_map(|request_id| {
        prop_oneof![
            Just(ConsentEvent::Request { request_id }),
            Just(ConsentEvent::ResponseApproved { request_id }),
            Just(ConsentEvent::ResponseDenied { request_id }),
            Just(ConsentEvent::Revocation { request_id }),
        ]
    })
}

fn sample_frame() -> Frame {
    Frame {
        frame_id: 0,
        timestamp_ms: 0,
        payload: vec![1, 2, 3],
    }
}

proptest! {
    /// After any sequence of events, the session's state is always one
    /// of the six defined variants (no invalid-state reachability).
    /// `observe_consent` may return Err — that's fine; the state must
    /// still be valid afterward.
    #[test]
    fn state_always_valid(events in prop::collection::vec(any_event(), 0..32)) {
        let mut s = session_with_key();
        for ev in events {
            let _ = s.observe_consent(ev);
            let state = s.consent_state();
            prop_assert!(matches!(
                state,
                ConsentState::LegacyBypass
                    | ConsentState::AwaitingRequest
                    | ConsentState::Requested
                    | ConsentState::Approved
                    | ConsentState::Denied
                    | ConsentState::Revoked,
            ));
        }
    }

    /// FRAME seal succeeds iff the state is LegacyBypass or Approved.
    /// Checked across arbitrary event sequences — the gate never
    /// diverges from the state.
    #[test]
    fn frame_seal_gate_matches_state(
        events in prop::collection::vec(any_event(), 0..16),
    ) {
        let mut s = session_with_key();
        for ev in events {
            let _ = s.observe_consent(ev);
        }
        let state = s.consent_state();
        let result = seal_frame(&sample_frame(), &mut s);
        match state {
            ConsentState::LegacyBypass | ConsentState::Approved => {
                prop_assert!(
                    result.is_ok(),
                    "state {state:?} must allow FRAME, got {result:?}",
                );
            }
            ConsentState::Revoked => {
                prop_assert!(
                    matches!(result, Err(WireError::ConsentRevoked)),
                    "Revoked must return ConsentRevoked, got {result:?}",
                );
            }
            ConsentState::AwaitingRequest
            | ConsentState::Requested
            | ConsentState::Denied => {
                prop_assert!(
                    matches!(result, Err(WireError::NoConsent)),
                    "state {state:?} must return NoConsent, got {result:?}",
                );
            }
        }
    }

    /// `AwaitingRequest` is only reached at session start — once the
    /// session has transitioned out via `Request`, no further event
    /// sequence returns to `AwaitingRequest`.
    #[test]
    fn awaiting_request_never_reached_again(
        events in prop::collection::vec(any_event(), 1..32),
    ) {
        let mut s = session_with_key();
        prop_assert_eq!(s.consent_state(), ConsentState::AwaitingRequest);
        let first = events[0];
        let _ = s.observe_consent(first);
        if s.consent_state() == ConsentState::AwaitingRequest {
            // First event was unsolicited OR a protocol violation that
            // left the state untouched — skip.
            return Ok(());
        }
        for ev in &events[1..] {
            let _ = s.observe_consent(*ev);
            prop_assert_ne!(s.consent_state(), ConsentState::AwaitingRequest);
        }
    }

    /// `observe_consent` never panics.
    #[test]
    fn observe_consent_never_panics(
        events in prop::collection::vec(any_event(), 0..64),
    ) {
        let mut s = session_with_key();
        for ev in events {
            let _ = s.observe_consent(ev);
        }
    }
}
