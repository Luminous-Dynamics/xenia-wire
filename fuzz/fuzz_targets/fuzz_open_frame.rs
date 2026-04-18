// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `open_frame()` — exercises AEAD + bincode deserialize
//! on the same input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::{open_frame, Session};

fuzz_target!(|data: &[u8]| {
    let mut session = Session::with_source_id([0; 8], 0);
    session.install_key([0xAB; 32]);
    let _ = open_frame(data, &mut session);
});
