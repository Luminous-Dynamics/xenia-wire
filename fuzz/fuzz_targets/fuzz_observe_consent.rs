// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Fuzz harness for `Session::observe_consent` under the draft-03
//! transition table (SPEC §12.6.1).
//!
//! Feeds arbitrary `Vec<ConsentEvent>` into a fresh ceremony-mode
//! session and exercises:
//!
//! 1. **No panic**: `observe_consent` must never panic regardless of
//!    input, even with `request_id` values at integer boundaries or
//!    adversarial interleavings of the four event kinds.
//! 2. **State is always valid**: after any sequence, `consent_state()`
//!    returns one of the six legal variants (Rust's enum exhaustiveness
//!    gives us this for free, but we read the state to exercise that
//!    code path).
//! 3. **Seal-gate consistency**: `seal` of a FRAME payload must succeed
//!    iff state ∈ {LegacyBypass, Approved}, fail with ConsentRevoked
//!    iff state == Revoked, and otherwise fail with NoConsent.
//! 4. **Idempotence of Ok**: if `observe_consent` returns `Ok(state)`,
//!    then `consent_state()` returns the same value.
//! 5. **Violation invariance**: if `observe_consent` returns `Err`,
//!    the state MUST be unchanged from before the call.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use xenia_wire::consent::ConsentEvent;
use xenia_wire::{Session, WireError};

#[derive(Arbitrary, Debug)]
enum FuzzEvent {
    Request(u64),
    ResponseApproved(u64),
    ResponseDenied(u64),
    Revocation(u64),
}

impl FuzzEvent {
    fn to_event(&self) -> ConsentEvent {
        match self {
            FuzzEvent::Request(id) => ConsentEvent::Request { request_id: *id },
            FuzzEvent::ResponseApproved(id) => ConsentEvent::ResponseApproved { request_id: *id },
            FuzzEvent::ResponseDenied(id) => ConsentEvent::ResponseDenied { request_id: *id },
            FuzzEvent::Revocation(id) => ConsentEvent::Revocation { request_id: *id },
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    ceremony_mode: bool,
    events: Vec<FuzzEvent>,
}

fuzz_target!(|input: Input| {
    let mut s = if input.ceremony_mode {
        Session::builder().require_consent(true).build()
    } else {
        Session::new()
    };
    s.install_key([0x42; 32]);

    for fe in &input.events {
        let event = fe.to_event();
        let state_before = s.consent_state();
        let result = s.observe_consent(event);
        let state_after = s.consent_state();

        match result {
            Ok(returned) => {
                // Idempotence: returned state must match readback.
                assert_eq!(returned, state_after, "observe_consent Ok state mismatch");
            }
            Err(_violation) => {
                // Violation invariance: state is unchanged.
                assert_eq!(
                    state_before, state_after,
                    "violation must NOT mutate session state"
                );
            }
        }

        // Frame-gate consistency — must agree with the current state.
        use xenia_wire::consent::ConsentState;
        let frame = xenia_wire::Frame {
            frame_id: 0,
            timestamp_ms: 0,
            payload: vec![],
        };
        let seal_res = xenia_wire::seal_frame(&frame, &mut s);
        match (state_after, &seal_res) {
            (ConsentState::LegacyBypass | ConsentState::Approved, Ok(_)) => {}
            (ConsentState::Revoked, Err(WireError::ConsentRevoked)) => {}
            (
                ConsentState::AwaitingRequest | ConsentState::Requested | ConsentState::Denied,
                Err(WireError::NoConsent),
            ) => {}
            other => panic!("seal gate inconsistent with state: {other:?}"),
        }
    }
});
