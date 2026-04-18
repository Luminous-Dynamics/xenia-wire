// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `Session::open()` with arbitrary input.
//!
//! Goal: ensure no panic on any byte sequence. A receiver must be
//! DoS-resistant to whatever the network throws at it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::Session;

fuzz_target!(|data: &[u8]| {
    let mut session = Session::with_source_id([0; 8], 0);
    session.install_key([0xAB; 32]);
    let _ = session.open(data);
});
