// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Property tests for the consent state machine.
//!
//! Fuzzes arbitrary sequences of [`ConsentEvent`]s into a session and
//! asserts:
//!
//! - Terminal states (`Denied`, `Revoked`) stay terminal — no event
//!   transitions out of them.
//! - `can_seal_frame` decisions match the SPEC §12.7 rules for the
//!   current state.
//! - `ConsentState::Pending` and `ConsentState::Approved` are the only
//!   states where application FRAME seals succeed.

#![cfg(all(feature = "consent", feature = "reference-frame"))]

use proptest::prelude::*;
use xenia_wire::consent::{ConsentEvent, ConsentState};
use xenia_wire::{seal_frame, Frame, Session, WireError};

fn session_with_key() -> Session {
    let mut s = Session::new();
    s.install_key([0x42; 32]);
    s
}

fn any_event() -> impl Strategy<Value = ConsentEvent> {
    prop_oneof![
        Just(ConsentEvent::Request),
        Just(ConsentEvent::ResponseApproved),
        Just(ConsentEvent::ResponseDenied),
        Just(ConsentEvent::Revocation),
    ]
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
    /// of the five defined variants (no invalid-state reachability).
    #[test]
    fn state_always_valid(events in prop::collection::vec(any_event(), 0..32)) {
        let mut s = session_with_key();
        for ev in events {
            let state = s.observe_consent(ev);
            prop_assert!(matches!(
                state,
                ConsentState::Pending
                    | ConsentState::Requested
                    | ConsentState::Approved
                    | ConsentState::Denied
                    | ConsentState::Revoked,
            ));
        }
    }

    /// `Denied` is terminal — no event sequence transitions out of it.
    #[test]
    fn denied_is_terminal(
        tail in prop::collection::vec(any_event(), 0..32),
    ) {
        let mut s = session_with_key();
        // Drive to Denied.
        s.observe_consent(ConsentEvent::Request);
        s.observe_consent(ConsentEvent::ResponseDenied);
        prop_assert_eq!(s.consent_state(), ConsentState::Denied);
        // Any subsequent events must leave the state at Denied.
        for ev in tail {
            s.observe_consent(ev);
            prop_assert_eq!(s.consent_state(), ConsentState::Denied);
        }
    }

    /// `Revoked` is terminal — no event sequence transitions out of it.
    #[test]
    fn revoked_is_terminal(
        tail in prop::collection::vec(any_event(), 0..32),
    ) {
        let mut s = session_with_key();
        s.observe_consent(ConsentEvent::Request);
        s.observe_consent(ConsentEvent::ResponseApproved);
        s.observe_consent(ConsentEvent::Revocation);
        prop_assert_eq!(s.consent_state(), ConsentState::Revoked);
        for ev in tail {
            s.observe_consent(ev);
            prop_assert_eq!(s.consent_state(), ConsentState::Revoked);
        }
    }

    /// FRAME seal succeeds iff the state is Pending or Approved.
    /// Checked across arbitrary event sequences — the gate never
    /// diverges from the state.
    #[test]
    fn frame_seal_gate_matches_state(
        events in prop::collection::vec(any_event(), 0..16),
    ) {
        let mut s = session_with_key();
        for ev in events {
            s.observe_consent(ev);
        }
        let state = s.consent_state();
        let result = seal_frame(&sample_frame(), &mut s);
        match state {
            ConsentState::Pending | ConsentState::Approved => {
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
            ConsentState::Requested | ConsentState::Denied => {
                prop_assert!(
                    matches!(result, Err(WireError::NoConsent)),
                    "state {state:?} must return NoConsent, got {result:?}",
                );
            }
        }
    }

    /// Pending is only reached at session start — once the session has
    /// observed any event, it never returns to Pending (no way back).
    #[test]
    fn pending_never_reached_again(
        events in prop::collection::vec(any_event(), 1..32),
    ) {
        let mut s = session_with_key();
        // Drive one event to leave Pending (or stay, if it's an
        // unsolicited event).
        let first = events[0];
        s.observe_consent(first);
        // Requested is the only non-Pending reachable from Pending +
        // any single event. Unsolicited events (Response/Revocation
        // from Pending) are no-ops by design.
        if s.consent_state() == ConsentState::Pending {
            // The first event was unsolicited — skip this case.
            return Ok(());
        }
        // From here, any further event sequence must keep state != Pending.
        for ev in &events[1..] {
            s.observe_consent(*ev);
            prop_assert_ne!(s.consent_state(), ConsentState::Pending);
        }
    }
}
